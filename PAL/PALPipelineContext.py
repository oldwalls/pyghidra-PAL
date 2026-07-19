class PALPipelineContext:
    """
    Unified communication wrapper between PAL pipeline layers.

    Holds PALFunctionObject and all derived analysis products.
    """

    def __init__(self, pal_function):

        self.func = pal_function

        # Layer outputs
        self.resolver_state = None
        self.semantic_graph = None
        self.phi_map = None
        self.emitted_code = None

    # -----------------------------------------------------

    def attach_resolver(self, resolver_output):
        self.resolver_state = resolver_output
        self.func.resolver = resolver_output
        return self

    # -----------------------------------------------------

    def attach_semantic_graph(self, semantic_output):
        self.semantic_graph = semantic_output
        self.func.semantic = semantic_output
        return self

    # -----------------------------------------------------

    def attach_phi_map(self, phi_output):
        self.phi_map = phi_output
        self.func.phi_map = phi_output
        return self

    # -----------------------------------------------------

    def attach_emitted_code(self, code_lines):
        self.emitted_code = code_lines
        self.func.generated_python = code_lines
        return self
