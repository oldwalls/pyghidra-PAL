import PALlibrary
import PALSGLdecomp
import PALemitter
import PALSymbolResolver
import PALCompute
import PALPHIfolder
import PALSemanticGraphBuilder

# ============================================================================
# PAL FUNCTION ASCII REPORT
# Consumes FUNCTION INSPECTOR output and renders ASCII diagnostics
# ============================================================================

# ============================================================================
# PAL INSPECTOR
# Extracts structured debug information from PALFunctionObject
# ============================================================================

from pprint import pprint

class PALInspector:

    # ----------------------------------------------------------------
    # ENTRY POINT
    # ----------------------------------------------------------------

    @staticmethod
    def inspect(pal_function):

        """
        Extracts a debug-friendly structure from a PALFunctionObject.
        """

        data = {}

        data["name"] = getattr(pal_function, "name", "?")

        data["address"] = getattr(pal_function, "addr", 0)

        data["parameters"] = PALInspector._extract_parameters(pal_function)

        data["variables"] = PALInspector._extract_variables(pal_function)

        blocks = PALInspector._extract_blocks(pal_function)

        data["blocks"] = blocks

        data["operations"] = PALInspector._extract_operations(blocks)

        data["returns"] = PALInspector._extract_returns(blocks)

        return data

    # ----------------------------------------------------------------
    # PARAMETERS
    # ----------------------------------------------------------------

    @staticmethod
    def _extract_parameters(func):

        params = []

        for p in getattr(func, "parameters", []):

            params.append(p)

        return params

    # ----------------------------------------------------------------
    # VARIABLES
    # ----------------------------------------------------------------

    @staticmethod
    def _extract_variables(func):

        vars_ = []

        for v in getattr(func, "variables", []):

            vars_.append(v)

        return vars_

    # ----------------------------------------------------------------
    # BLOCKS
    # ----------------------------------------------------------------

    @staticmethod
    def _extract_blocks(func):

        blocks = []

        # Some PALFunctionObjects store blocks differently
        # so we try multiple access patterns safely.

        if hasattr(func, "blocks"):

            blocks = list(func.blocks)

        elif hasattr(func, "cfg"):

            cfg = func.cfg

            if hasattr(cfg, "nodes"):
                blocks = list(cfg.nodes.values())

        return blocks

    # ----------------------------------------------------------------
    # OPERATIONS
    # ----------------------------------------------------------------

    @staticmethod
    def _extract_operations(blocks):

        ops = []

        for b in blocks:

            block = getattr(b, "block", None)

            if block and hasattr(block, "ops"):

                ops.extend(block.ops)

            elif hasattr(b, "ops"):

                ops.extend(b.ops)

        return ops

    # ----------------------------------------------------------------
    # RETURN VALUES
    # ----------------------------------------------------------------

    @staticmethod
    def _extract_returns(blocks):

        returns = []

        for b in blocks:

            block = getattr(b, "block", None)

            ops = []

            if block and hasattr(block, "ops"):
                ops = block.ops

            elif hasattr(b, "ops"):
                ops = b.ops

            for op in ops:

                opcode = getattr(op, "opcode", "")

                if "RETURN" in opcode.upper():

                    if hasattr(op, "inputs") and op.inputs:
                        if len(op.inputs) >= 2:
                            returns.append(op.inputs[1])

        return returns

#=========================================================
class PALFunctionASCIIReport:

    WIDTH = 70

    # ----------------------------------------------------------------

    def __init__(self, pal_func):

        """
        inspector: result of FunctionInspector.inspect(function)
        """
        self.pal_func = pal_func
        inspector_data = PALInspector.inspect(pal_func)
        
        self.data = inspector_data

    # ----------------------------------------------------------------
    # FORMULA INSPECTOR (debug helper)
    # ----------------------------------------------------------------

    def _peek_formula(self, ssa_var):
        """
        Attempts to print the SSA formula that produced a variable.
        """

        if not ssa_var:
            return "?"

        try:

            # SSA variable usually has a defining operation
            op = getattr(ssa_var, "def_op", None)

            if not op:
                return f"{ssa_var.ssa_id}"

            opcode = op.opcode 

            inputs = []

            for inp in getattr(op, "inputs", []):

                if hasattr(inp, "ssa_id"):
                    inputs.append(f"{inp.ssa_id}")
                else:
                    inputs.append(str(inp))

            args = ", ".join(inputs)

            return f"{ssa_var.ssa_id} = {opcode}({args})"

        except Exception as e:
            return f"v{ssa_var.ssa_id} ? ({e})"
            

    # ----------------------------------------------------------------
    # PUBLIC ENTRY
    # ----------------------------------------------------------------

    def fmt_var(self, v):

        if hasattr(v, "ssa_id"):
            return f"{v.ssa_id}"

        name = getattr(v, "name", None)

        if name:
            return name

        return str(v)

    def render(self):

        lines = []

        lines += self._section("PAL FUNCTION INSPECTOR REPORT")

        lines += self._function_summary()

        lines += self._parameters()

        lines += self._variables()

        lines += self._blocks()

        lines += self._operations()
        lines += self._lifted_functions()

        lines += self._returns()

        lines.append("=" * self.WIDTH)

        return "\n".join(lines)

    # ----------------------------------------------------------------
    # SECTION HEADER
    # ----------------------------------------------------------------

    def _section(self, title):

        bar = "=" * self.WIDTH

        return [
            bar,
            title.center(self.WIDTH),
            bar,
        ]

    # ----------------------------------------------------------------
    # SUBSECTION HEADER
    # ----------------------------------------------------------------

    def _sub(self, title):

        return [
            "",
            title,
            "-" * len(title),
        ]

    # ----------------------------------------------------------------
    # FUNCTION SUMMARY
    # ----------------------------------------------------------------

    def _function_summary(self):

        #d = self.data
        d = self.pal_func

        #print(">>>>>> PAL func_name: ", self.pal_func.func_name)
        
        
    
        lines = self._sub("Function Summary")
        
        lines.append(f"Name        : {self.pal_func.func_name}")
        lines.append(f"Address     : {hex(self.pal_func.function_address)}")
        lines.append(f"Parameters  : {len(self.pal_func.parameters)}")
        lines.append(f"Variables   : {len(self.pal_func.vars)}")
        lines.append(f"Blocks      : {len(self.pal_func.blocks)}")
        
        return lines

    # ----------------------------------------------------------------
    # PARAMETERS
    # ----------------------------------------------------------------

    def _parameters(self):

        params = self.data.get("parameters", [])

        lines = self._sub("Parameters")

        if not params:
            lines.append("None")
            return lines

        for p in params:

            name = getattr(p, "name", "?")
            ssa  = getattr(p, "ssa_id", "?")

            lines.append(f"{self.fmt_var(p)}")

        return lines

    # ----------------------------------------------------------------
    # VARIABLES
    # ----------------------------------------------------------------

    def _variables(self):

        vars_ = self.pal_func.vars

        lines = self._sub("Variables")

        if not vars_:
            lines.append("None")
            return lines

        for v in vars_:

            lines.append(f"{self.fmt_var(v)}")

        return lines

    # ----------------------------------------------------------------
    # BASIC BLOCKS
    # ----------------------------------------------------------------

    def _blocks(self):

        blocks = self.data.get("blocks", [])

        lines = self._sub("Basic Blocks")

        if not blocks:
            lines.append("None")
            return lines

        for b in blocks:

            addr = getattr(b, "addr", 0)

            succs = getattr(b, "successors", [])

            succ_txt = ", ".join(hex(s.addr) for s in succs)

            lines.append(f"[{hex(addr)}] -> [{succ_txt}]")

        return lines

    # ----------------------------------------------------------------
    # OPERATIONS
    # ----------------------------------------------------------------

    def _operations(self):

        ops = self.data.get("operations", [])

        lines = self._sub("Operations")

        if not ops:
            lines.append("None")
            return lines

        for op in ops:

            opcode = getattr(op, "opcode", "?")

            out = getattr(op, "output", None)

            out_txt = f"{out.ssa_id}" if out else "-"

            inputs = []

            for i in getattr(op, "inputs", []):

                if hasattr(i, "ssa_id"):
                    inputs.append(f"{i.ssa_id}")
                else:
                    inputs.append(str(i))

            args = ", ".join(inputs)

            lines.append(f"{out_txt:<8} = {opcode}({args})")

        return lines

    # ----------------------------------------------------------------
    # RETURNS
    # ----------------------------------------------------------------

    def _returns(self):

        r = self.data.get("returns", [])

        lines = self._sub("Returns")

        if not r:
            lines.append("None")
            return lines

        for v in r:

            lines.append(f"{self.fmt_var(v)}")

        return lines

    # ----------------------------------------------------------------
    # LIFTED FUNCTIONS
    # ----------------------------------------------------------------

    def _lifted_functions(self):

        r = list(self.pal_func.ssa_map.values())

        lines = self._sub("VAR Formulas")
        print(">>>>>>> r.list : ", r)
        if not r:
            lines.append("No Lifted Functions")
            return lines

        for v in r:

            lines.append(f"{self._peek_formula(v)}")

        return lines



#-------------------------------

class PALDecompilerPipeline:
    """
    Unified PAL decompiler pipeline dispatcher.

    Runs layers sequentially while storing results
    inside the PALFunctionObject.
    """

    # ---------------------------------------------------------
    # CONSTRUCTION
    # ---------------------------------------------------------

    def __init__(self,
                 ghidra_func=None,
                 program=None,
                 decompiler_interface=None,
                 monitor=None):

        self.ghidra_func = ghidra_func
        self.program = program
        self.decompiler_interface = decompiler_interface
        self.monitor = monitor

        self.PAL = None

    # ---------------------------------------------------------
    # LAYER 0
    # PAL Lift
    # ---------------------------------------------------------

    def run_lift(self):

        self.PAL = PALlibrary.PALLifter(
            self.ghidra_func,
            self.program,
            self.decompiler_interface,
            self.monitor
        )

        self.PAL = self.PAL.lift()

        #from PALlibrary import debug_dump_indirect_custody
        """
        PALlibrary.debug_dump_indirect_custody(
            self.PAL,
            include_contracts=False,
        )       
        """
        return self.PAL

    # ---------------------------------------------------------
    # LAYER 1
    # CFG Construction
    # ---------------------------------------------------------

    def run_cfg(self):

        self.PAL.cfg = PALlibrary.FunctionCFG(self.PAL)

         
        return self.PAL.cfg

    # ---------------------------------------------------------
    # LAYER 2
    # Symbol Resolver
    # ---------------------------------------------------------

    def run_resolver(self):

        resolver = PALSymbolResolver.PALSymbolResolver(
            self.PAL,
            self.program
        )

        resolver.resolve()

        PALSymbolResolver.debug_dump_indirect_storage_resolver(self.PAL)



        #PALlibrary.debug_dump(self.PAL)

        return

    # ---------------------------------------------------------
    # LAYER 3
    # Structuring / ExecTree Builder
    # ---------------------------------------------------------

    def run_structurer(self):

        # Use the canonical standalone SGL module.
        # Do NOT use PALPyDecompiler.PALSGLDecompiler here;
        # that file contains an older duplicate implementation.
        structurer = PALSGLdecomp.PALSGLDecompiler(self.PAL)

        root = structurer.build()

        # Canonical field used by the emitter.
        self.PAL.exec_root = root

        # Compatibility alias for older code.
        self.PAL.exec_tree = root

        # Optional: useful during this recovery phase.
        #if hasattr(structurer, "debug_print"):
        #    structurer.debug_print()


        #PALSGLdecomp.debug_sidecar(self.PAL)


        return root

    # ---------------------------------------------------------
    # LAYER 4
    # Semantic Graph Builder
    # ---------------------------------------------------------

    def run_semantic_graph(self):

        builder = PALSemanticGraphBuilder.PALSemanticGraphBuilder(self.PAL)

        semantic_result = builder.run()

        self.PAL.semantic = semantic_result

        return semantic_result

    # ---------------------------------------------------------
    # LAYER 5
    # PHI Folder
    # ---------------------------------------------------------

    def run_phi_folder(self):

        #var_nodes, phi_nodes = self.PALfunc.semantic[:2]

        folder = PALPHIfolder.PALPHIfolder(
            self.PAL
        )

        varmap = folder.run()

        self.PAL.varmap = varmap



        #PALPHIfolder.debug_condition_custody(self.PAL, verbose=True)


        return varmap

    # ---------------------------------------------------------
    # LAYER 6
    # Python Emitter
    # ---------------------------------------------------------

    def run_emitter(self):
        
        emitter = PALemitter.PALemitter(self.PAL)
        views = emitter.emit_function_pair()



        emitter.debug_dump_storage_custody(verbose=True)



        readable_code = views["readable"]
        executable_code = views["executable"]

        #emitter = PALemitter.PALemitter(self.PAL)

        #lines = emitter.emit_function()

        # self.PAL.pycode_digest = readable_code
        # self.PAL.pycode_exec  = executable_code
        
        """
        pprint(self.PAL.code_document_debug)
        pprint(self.PAL.emitter_dual_path_debug)

        doc = self.PAL.code_document

        for record in doc.projection("readable").statements:
            pprint(record.as_dict())
        
        
        snapshot_digest = self.PAL.code_document.save_bundle(
            f"{self.PAL.func_name}.pal.json"
        )

        #print(snapshot_digest)        
        """
        
        return readable_code, executable_code


    def run_raw_audit(self):
        import PALRawAudit

        audit = PALRawAudit.PALRawAudit(
            pal_function=self.PAL,
            program=self.program,
            decompiler_interface=self.decompiler_interface,
            monitor=self.monitor,
        )

        audit.run([0x10127f, 0x1011b6, 0x101219, 0x10120f, 0x101221, 0x101284, 0x10127F])







        audit.print_report()
        
        
        self.PAL.raw_audit = audit.report

        return audit.report


    # ---------------------------------------------------------
    # FULL PIPELINE
    # ---------------------------------------------------------

    def run_all(self):

        self.run_lift()
        self.run_cfg()
        self.run_resolver()
        
        self.run_raw_audit()
        
        analyzer = PALCompute.PALComputeAnalyzer(self.PAL)
        analyzer.run()
        PALCompute.debug_dump_compute(self.PAL)        
        
        self.run_semantic_graph()
        self.run_structurer()
        self.run_phi_folder()
        
        pprint(self.PAL.phi_compute_debug["summary"])
        pprint(self.PAL.phi_compute_debug["warnings"])
        
                
        self.run_emitter()
        
        #pprint(self.PAL.emitter_c_truth_debug["summary"])
        #pprint(self.PAL.emitter_c_truth_debug["warnings"])
        #pprint(self.PAL.emitter_c_truth_debug["unrendered_helper_op_keys"])
                
        debug = self.PAL.emitter_c_truth_debug

        #pprint(debug["summary"])
        #pprint(debug["unrendered_contract_details"])
        """
        for probe in debug["raw_condition_probes"]:
            text = str(probe)
            if "61440" in text or "f000" in text.lower():
                pprint(probe)        
        """
  
        #self.run_raw_audit()
        
        #PALlibrary.debug_dump_numeric_evidence(self.PAL)
        
        #print("\n".join(self.PAL.pycode))

        return self.PAL.pycode_readable, self.PAL.pycode_executable

    
    def debug_print(self, verbose=False):

        pf = self.PAL

        if pf is None:
            print("Pipeline not initialized.")
            return

        print("\n")
        print("=" * 70)
        print("PAL DECOMPILER PIPELINE :: INTERNAL STATE")
        print("=" * 70)
        
        """
        self._dbg_function_summary(pf)
        self._dbg_cfg(pf)
        self._dbg_dominator_tree(pf)
        self._dbg_exec_tree(pf)
        self._dbg_semantic_graph(pf)
        self._dbg_phi_groups(pf)
        self._dbg_varmap(pf)
        self._dbg_conditions(pf)
        self._dbg_exec_tree(pf)
        self._dbg_emitter(pf)
        """
        print("\n<<<<<<<< INSPECTOR >>>>>>>>\n")

        bulletin = PALFunctionASCIIReport(pf)
        print(">>>>>> before render:::")
        report_text = bulletin.render()
        print(f"{report_text}")


    def _dbg_function_summary(self, pf):

        print("\n[LAYER 0] PAL FUNCTION")
        print("-" * 70)

        print(f"Name        : {getattr(pf,'func_name','?')}")
        print(f"Entry       : {getattr(pf,'entry_addr','?')}")
        print(f"Parameters  : {len(getattr(pf,'parameters',[]))}")

        vars_container = getattr(pf,"vars",{})
        count = len(vars_container) if isinstance(vars_container,dict) else len(list(vars_container))

        print(f"Variables   : {count}")
        
        
    def _dbg_cfg(self, pf):

        print("\n[LAYER 1] CONTROL FLOW GRAPH")
        print("-" * 70)

        cfg = getattr(pf,"cfg",None)

        if not cfg:
            print("CFG not built.")
            return

        for node_id,node in cfg.nodes.items():

            succ = getattr(node,"successors",[])
            succ_ids = [getattr(s,"addr",id(s)) for s in succ]

            line = f"[{node_id}] ---> {succ_ids}"

            if node == cfg.entry:
                line += "   (ENTRY)"

            if node in cfg.exit_nodes:
                line += "   (EXIT)"

            print(line)
            

    def _dbg_dominator_tree(self, pf):

        print("\nDOMINATOR TREE")
        print("-" * 70)

        cfg = getattr(pf,"cfg",None)

        if not cfg or not getattr(cfg,"idom",None):
            print("Dominators unavailable.")
            return

        for node,parent in cfg.idom.items():

            nid = getattr(node,"addr",node)
            pid = getattr(parent,"addr",parent) if parent else None

            print(f"{nid}  <-  {pid}")
            
                
                
    def _dbg_exec_tree(self, pf):

        print("\n[LAYER 3] EXECUTION STRUCTURE")
        print("-" * 70)

        root = getattr(pf,"exec_tree",None)

        if not root:
            print("Execution tree not generated.")
            return

        def walk(node,depth=0):

            indent = "  "*depth
            kind = getattr(node,"kind","?")

            print(f"{indent}|- {kind}")

            for child in getattr(node,"children",[]):
                walk(child,depth+1)

        walk(root)
        
    
    def _dbg_semantic_graph(self, pf):

        print("\n[LAYER 4] SEMANTIC GRAPH")
        print("-" * 70)
        """
        var_nodes = getattr(pf, "var_nodes", None)

        if not var_nodes:
            print("Semantic graph unavailable.")
            return

        total = len(var_nodes)
        
        phi_nodes = [
            n for n in var_nodes.values()
            if getattr(n, "opcode", None) == "MULTIEQUAL"
        ]
        
        print("Formula Nodes :", total)
        print("PHI Nodes     :", len(phi_nodes))

        print("\n[Sample Nodes]")
        for i, node in enumerate(var_nodes.values()):
            if i >= 10:
                break

            sid = getattr(node.var, "ssa_id", "?")
            opcode = getattr(node, "opcode", "?")

            inputs = []
            for inp in getattr(node, "inputs", []):
                if hasattr(inp, "var"):
                    inputs.append(getattr(inp.var, "ssa_id", "?"))
                else:
                    inputs.append(str(inp))

        print(f"{sid} = {opcode}({inputs})")
        """
        
    def _dbg_phi_groups(self, pf):

        print("\nPHI GROUPS")
        print("-" * 70)
        """
        var_nodes = getattr(pf, "var_nodes", None)

        if not var_nodes:
            print("No semantic graph.")
            return

        phi_nodes = [
            n for n in var_nodes.values()
            if getattr(n, "opcode", None) == "MULTIEQUAL"
        ]

        if not phi_nodes:
            print("No PHI nodes found.")
            return

        for phi in phi_nodes:

            out_sid = getattr(phi.var, "ssa_id", "?")

            inputs = []
            for inp in getattr(phi, "inputs", []):
                if hasattr(inp, "var"):
                    inputs.append(getattr(inp.var, "ssa_id", "?"))
                else:
                    inputs.append(str(inp))

            print(f"v_{out_sid} <- {[f'v_{i}' for i in inputs]}")
        """

    def _dbg_exec_tree(self, pf):

        print("\n[DEBUG] EXEC TREE")
        print("-" * 70)

        root = getattr(pf, "exec_root", None)

        if not root:
            print("No exec tree.")
            return

        def walk(node, depth=0):

            indent = "  " * depth

            kind = getattr(node, "kind", type(node).__name__)

            header = getattr(node, "header", None)
            has_then = hasattr(node, "then_branch")
            has_else = hasattr(node, "else_branch")
            has_body = hasattr(node, "body")

            print(f"{indent}{kind}")
            print(f"{indent}  header: {bool(header)}")
            print(f"{indent}  then  : {has_then}")
            print(f"{indent}  else  : {has_else}")
            print(f"{indent}  body  : {has_body}")

            for c in getattr(node, "children", []):
                walk(c, depth + 1)

        walk(root)
    


    def _dbg_conditions(self, pf):

        print("\n[DEBUG] CONDITIONS")
        print("-" * 70)

        root = getattr(pf, "exec_root", None)
        if not root:
            print("No exec tree.")
            return

        def walk(node):

            kind = getattr(node, "kind", type(node).__name__)

            if "If" in kind or "Loop" in kind:

                header = getattr(node, "header", None)
                block = getattr(header, "block", header)

                print(f"\nNode: {kind}")

                for op in getattr(block, "ops", []):
                    if getattr(op, "opcode", "") == "CBRANCH":
                        inputs = getattr(op, "inputs", [])

                        print("  RAW inputs:", inputs)

                        if len(inputs) >= 2:
                            var = inputs[1]
                            sid = getattr(var, "ssa_id", None)

                            print("  SSA:", sid)

                            if sid in pf.var_nodes:
                                node = pf.var_nodes[sid]
                                print("  Semantic:", node.opcode, node.inputs)
                            else:
                                print("  ❌ Not in semantic graph")

            for c in getattr(node, "children", []):
                walk(c)

        walk(root)
            
                    
    def _dbg_varmap(self, pf):

        print("\n[LAYER 5] VARIABLE FOLDING")
        print("-" * 70)

        varmap = getattr(pf,"var_map",None)

        if not varmap:
            print("Var map not built.")
            return

        groups = {}

        for var,name in varmap.items():
            groups.setdefault(name,[]).append(var)

        for leader,members in groups.items():

            mnames = [getattr(v,"name",str(v)) for v in members]

            print(f"{leader} : {mnames}")

    def _dbg_emitter(self, pf):

        print("\n[LAYER 6] GENERATED CODE")
        print("-" * 70)

        code = getattr(pf,"pycode",None)

        if not code:
            print("Emitter not executed.")
            return

        preview = min(20,len(code))

        for i in range(preview):
            print(code[i])
        
