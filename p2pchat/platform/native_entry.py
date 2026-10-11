"""Fixed PyInstaller entrypoint; no user-provided modules or commands."""
import runpy

if __name__ == "__main__":
    runpy.run_module("p2pchat.native.bridge", run_name="__main__")
