# Generated PAL executable state-machine entry.

from PAL_project_runtime import PALProjectRuntime


def run(function=None, arguments=(), variadic_arguments=()):
    runtime = PALProjectRuntime()
    return runtime.run(function, arguments, variadic_arguments)


def main():
    result = run()
    print("\nPAL rendition:", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
