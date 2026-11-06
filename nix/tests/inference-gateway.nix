# Integration test for the inference gateway (ADR-0020) against a real Ollama
# server: services.ollama runs on the test VM with qwen3:0.6b loaded from the
# nix store (./ollama-model.nix), and a real sodabox VM calls it through its
# gateway the way a client in the guest would.
#
# It checks the whole path (guest → passt → TPROXY → gateway → Ollama), both
# API formats against a real server (Ollama's native API, and its
# OpenAI-compatible /v1), that the tokens Ollama reports are booked to the
# quota ledger, that a used-up quota is refused, that unlimited use is
# unmetered, and that revoking access hides the gateway again.
#
# Like persist-modes, the sodabox guest is prebuilt here (the test VM has no
# network) and handed to sodabox through its SODABOX_NIX_BUILD seam. Needs
# nested virtualization on the build host.
# Run: nix build .#checks.x86_64-linux.inference-gateway
{ nixpkgs, sodabox }:
{ pkgs, lib, ... }:
let
  model = pkgs.callPackage ./ollama-model.nix { } {
    model = "qwen3";
    tag = "0.6b";
    hash = "sha256-X7UFNEWOoH5tdfeFK9AYQ90yOvRkHbCwpTVrkH7RqDw=";
  };

  guest = import ../guest/mkGuest.nix {
    guestDir = ./guest-gateway;
    system = pkgs.stdenv.hostPlatform.system;
    nixpkgs = nixpkgs.outPath;
  };

  fakeNixBuild = pkgs.writeShellScript "fake-nix-build" ''
    printf '%s\n' ${guest.kernel} ${guest.initrd} ${guest.store} ${guest.toplevel}
  '';

  # sodabox as the unprivileged user, with a short runtime dir (unix socket
  # paths must stay under SUN_LEN).
  sb = pkgs.writeShellScriptBin "sb" ''
    exec ${pkgs.util-linux}/bin/runuser -u alice -- env \
      HOME=/home/alice XDG_RUNTIME_DIR=/run/sb \
      SODABOX_NIX_BUILD=${fakeNixBuild} \
      ${lib.getExe sodabox} "$@"
  '';

  # Two providers for the same server: Ollama's native API, and its
  # OpenAI-compatible /v1 (with a credential command, which Ollama ignores,
  # so the credential path runs too).
  ollamaProvider = pkgs.writeText "ollama.toml" ''
    description = "Ollama on the test VM, native API"
    api = "ollama"
    base_url = "http://127.0.0.1:11434"
  '';
  ollamaOpenaiProvider = pkgs.writeText "ollama-openai.toml" ''
    description = "Ollama on the test VM, OpenAI-compatible API"
    api = "openai"
    base_url = "http://127.0.0.1:11434/v1"
    auth = { command = ["echo", "host-side-key"] }
  '';
in
{
  name = "sodabox-inference-gateway";

  nodes.machine = {
    virtualisation = {
      memorySize = 6144;
      cores = 4;
      diskSize = 4096;
    };
    boot.kernelModules = [
      "kvm-amd"
      "kvm-intel"
    ];

    services.ollama.enable = true;
    # Lay the model out in Ollama's (writable) models dir as symlinks into the
    # store: no 500 MB copy, and Ollama sees an ordinary pulled model.
    systemd.services.ollama.preStart = ''
      mkdir -p "$OLLAMA_MODELS"
      cp -rsf --no-preserve=mode ${model}/. "$OLLAMA_MODELS"/
    '';

    users.users.alice = {
      isNormalUser = true;
      extraGroups = [ "kvm" ];
    };
    systemd.tmpfiles.rules = [ "d /run/sb 0700 alice users -" ];

    environment.systemPackages = [
      sb
      pkgs.openssh
      pkgs.curl
    ];
  };

  testScript = ''
    import json
    import shlex

    VM = "gw"
    D = f"/home/alice/.local/share/sodabox/{VM}"
    URL = "http://inference.sodabox.internal"

    def sb(args):
        return machine.succeed(f"sb {args} --vm {VM}")

    def guest(cmd):
        return machine.succeed(f"sb ssh {VM} -- {shlex.quote(cmd)}")

    def request(path, body, stream=False):
        """POST `body` from inside the guest; returns (status, response text)."""
        payload = shlex.quote(json.dumps(body))
        out = guest(
            f"curl -sS -m 600 -o /tmp/resp -w '%{{http_code}}'"
            " -H 'content-type: application/json'"
            " -H 'authorization: Bearer guest-placeholder'"
            f" -d {payload} {URL}{path}; echo; cat /tmp/resp"
        )
        status, _, text = out.partition("\n")
        return int(status), text

    def ledger():
        text = machine.succeed(f"cat {D}/quota.jsonl")
        return [json.loads(l) for l in text.splitlines() if l.strip()]

    def usage_entries(alias):
        return [e for e in ledger() if e["alias"] == alias and e["reason"] in ("usage", "unmetered")]

    def wait_for_usage(alias, n):
        """Usage is booked when the response body ends, just after curl returns."""
        machine.wait_until_succeeds(
            f"test $(grep -c '\"alias\":\"{alias}\".*\"reason\":\"\\(usage\\|unmetered\\)\"' {D}/quota.jsonl) -ge {n}",
            timeout=60,
        )

    def balance(alias):
        return sum(e["delta"] for e in ledger() if e["alias"] == alias)

    def chat(alias, content="Say hi."):
        return {"model": alias, "messages": [{"role": "user", "content": content}]}

    machine.wait_for_unit("multi-user.target")
    machine.succeed("test -c /dev/kvm")

    with subtest("ollama serves qwen3:0.6b from the nix store"):
        machine.wait_for_unit("ollama.service")
        machine.wait_for_open_port(11434)
        tags = json.loads(machine.succeed("curl -sf http://127.0.0.1:11434/api/tags"))
        assert [m["name"] for m in tags["models"]] == ["qwen3:0.6b"], tags

    with subtest("set up a VM with the gateway"):
        for name, src in [("ollama", "${ollamaProvider}"), ("ollama-openai", "${ollamaOpenaiProvider}")]:
            machine.succeed(
                f"runuser -u alice -- install -D -m 0644 {src}"
                f" /home/alice/.config/sodabox/providers/{name}.toml"
            )
        machine.succeed(f"sb create {VM} --disk 1G --home-disk 256M --cpus 1")
        sb("gateway enable")
        sb("allow service inference")
        sb("model add qwen ollama/qwen3:0.6b --initial-quota 100k")
        sb("model add qwen-oa ollama-openai/qwen3:0.6b --initial-quota 100k")
        sb("model add tiny ollama/qwen3:0.6b --initial-quota 1")
        machine.succeed(f"sb start {VM} --net >/tmp/start.log 2>&1")
        machine.wait_until_succeeds(f"sb ssh {VM} -- true", timeout=900)

    with subtest("the guest resolves the gateway and sees only its aliases"):
        assert "10.0.2.4" in guest("getent hosts inference.sodabox.internal")
        tags = json.loads(guest(f"curl -sf {URL}/api/tags"))
        assert sorted(m["name"] for m in tags["models"]) == ["qwen", "tiny"], tags
        models = json.loads(guest(f"curl -sf {URL}/v1/models"))
        assert [m["id"] for m in models["data"]] == ["qwen-oa"], models

    with subtest("ollama native chat, not streamed"):
        body = chat("qwen") | {"stream": False, "think": False, "options": {"num_predict": 8}}
        status, text = request("/api/chat", body)
        assert status == 200, text
        r = json.loads(text)
        assert r["done"] and r["eval_count"] > 0 and r["prompt_eval_count"] > 0, r
        wait_for_usage("qwen", 1)
        booked = usage_entries("qwen")[-1]
        assert booked["tokens"] == r["prompt_eval_count"] + r["eval_count"], (booked, r)

    with subtest("ollama native chat, streamed (Ollama's default)"):
        status, text = request("/api/chat", chat("qwen") | {"think": False, "options": {"num_predict": 8}})
        assert status == 200, text
        lines = [json.loads(l) for l in text.splitlines() if l.strip()]
        assert len(lines) > 1 and lines[-1]["done"], lines
        wait_for_usage("qwen", 2)
        assert usage_entries("qwen")[-1]["tokens"] == lines[-1]["prompt_eval_count"] + lines[-1]["eval_count"]

    with subtest("openai-compatible streaming gets usage the client didn't ask for"):
        status, text = request("/v1/chat/completions", chat("qwen-oa") | {"stream": True, "max_tokens": 8})
        assert status == 200, text
        assert "data: [DONE]" in text, text
        chunks = [json.loads(l[len("data:"):]) for l in text.splitlines()
                  if l.startswith("data:") and "[DONE]" not in l]
        usage = [c["usage"] for c in chunks if c.get("usage")]
        assert usage, "the gateway's include_usage didn't make Ollama report usage"
        wait_for_usage("qwen-oa", 1)
        u = usage[-1]
        cached = (u.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
        assert usage_entries("qwen-oa")[-1]["tokens"] == u["prompt_tokens"] - cached + u["completion_tokens"]

    with subtest("balances match what was booked"):
        for alias in ["qwen", "qwen-oa"]:
            used = sum(e["tokens"] for e in usage_entries(alias))
            assert balance(alias) == 100_000 - used, (alias, balance(alias), used)
        shown = sb("quota show")
        assert "qwen-oa" in shown, shown

    with subtest("a used-up quota is refused before reaching Ollama"):
        # Balance 1: the first request is let through and takes it below zero.
        status, text = request("/api/generate", {"model": "tiny", "prompt": "Hi", "stream": False, "think": False, "options": {"num_predict": 4}})
        assert status == 200, text
        wait_for_usage("tiny", 1)
        assert balance("tiny") < 0
        status, text = request("/api/generate", {"model": "tiny", "prompt": "Hi", "stream": False})
        assert status == 403, (status, text)
        assert "soda quota grant tiny" in json.loads(text)["error"], text
        assert len(usage_entries("tiny")) == 1

    with subtest("unlimited use is served and booked as unmetered"):
        before = balance("tiny")
        sb("quota unlimited tiny")
        status, text = request("/api/generate", {"model": "tiny", "prompt": "Hi", "stream": False, "think": False, "options": {"num_predict": 4}})
        assert status == 200, text
        wait_for_usage("tiny", 2)
        last = usage_entries("tiny")[-1]
        assert last["reason"] == "unmetered" and last["delta"] == 0 and last["tokens"] > 0, last
        assert balance("tiny") == before

    with subtest("an unknown model is a 404 in the route's format"):
        status, text = request("/v1/chat/completions", chat("gpt-9"))
        assert status == 404 and json.loads(text)["error"]["code"] == "model_not_found", text

    with subtest("revoking access hides the gateway"):
        sb("revoke inference")
        # The guest may cache the answer for its TTL (30 s).
        machine.wait_until_succeeds(
            f"sb ssh {VM} -- '! getent hosts inference.sodabox.internal'", timeout=120
        )
        machine.fail(f"sb ssh {VM} -- 'curl -sf -m 10 http://10.0.2.4/api/tags'")
        logs = machine.succeed(f"sb logs {VM}")
        assert "BLOCK     tcp 10.0.2.4:80" in logs, logs

    machine.succeed(f"sb stop {VM}")
  '';
}
