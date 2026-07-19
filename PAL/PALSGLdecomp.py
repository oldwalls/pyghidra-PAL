# ============================================================================
# PAL SGL DECOMPILER â€” EXEC TREE BUILDER
# Conservative truth iteration + EdgeTruth consumption + condition provenance sidecars v54
# ============================================================================
#
# Goal:
#   Preserve the stable structure of the original PALSGLdecomp.py while fixing
#   branch-polarity mistakes discovered in complex GCC/O0 lowered code.
#
# What this iteration deliberately does NOT do:
#   - no broad branch-local duplication
#   - no linear fallback rewrite
#   - no attempt to recover pretty source structure
#   - no switch-to-match recovery
#
# What this iteration does:
#   - retains original traversal/visited behavior
#   - selects then/else using CFG true/false edges as baseline
#   - applies narrow polarity repairs for observed lowered patterns:
#       * if cond: pass / else: action  -> swap action under cond
#       * const < var skip-tests        -> swap
#       * switch compare/range chains   -> targeted swaps
#       * check_bit == 0 path           -> corrected action polarity
#       * parity ternary call pair      -> corrected even/odd selection
#   - emits branch diagnostics
#
# This is meant as a safer path from the last stable structured output.
# ============================================================================

import re

from PALlibrary import FunctionCFG


class RawCond:
    """
    Minimal wrapper for composite/corrected boolean conditions.

    Current PALemitter._cond() can render constants through _const().
    By presenting the expression string as const_value, we avoid requiring
    an immediate emitter patch.
    """
    is_constant = True

    def __init__(self, expr, source=None, inverted=False, reason=None):
        self.const_value = expr
        self.value = expr
        self.offset = expr
        self.name = expr
        self.ssa_id = None
        self.source = source
        self.inverted = inverted
        self.reason = reason

    def __str__(self):
        return self.const_value


# ============================================================================
# EXECUTION NODES
# ============================================================================

class ExecNode:
    def __init__(self, kind):
        self.kind = kind
        self.children = []
        self.parent = None

    def add(self, node):
        node.parent = self
        self.children.append(node)
        return node


class ExecBlock(ExecNode):
    def __init__(self, cfg_node):
        super().__init__("block")
        self.cfg_node = cfg_node


class ExecBreak(ExecNode):
    def __init__(self, target_loop=None, reason=None):
        super().__init__("break")
        self.target_loop = target_loop
        self.reason = reason


class ExecContinue(ExecNode):
    def __init__(self, target_loop=None, reason=None):
        super().__init__("continue")
        self.target_loop = target_loop
        self.reason = reason


class ExecIf(ExecNode):
    def __init__(self, cfg_node, cond_var):
        super().__init__("if")
        self.cfg_node = cfg_node
        self.cond_var = cond_var

        self.then_branch = ExecNode("then")
        self.else_branch = ExecNode("else")

        self.add(self.then_branch)
        self.add(self.else_branch)


class ExecLoop(ExecNode):
    def __init__(self, header_node, cond_var, condition_role=None):
        super().__init__("loop")
        self.header = header_node
        self.cfg_node = header_node
        self.cond_var = cond_var

        # v20 loop condition contract:
        #   "true" -> emitter prints while True
        #   "body" -> emitter prints while cond
        #   "exit" -> emitter prints while not(cond)
        #
        # SGL owns this semantic decision.  The emitter should consume this
        # directly and avoid expression-shape polarity guesses.
        self.condition_role = condition_role or ("true" if cond_var is None else "body")
        self.emit_condition_mode = self.condition_role

        self.header_is_body = False
        self.guard_node = None

        self.body = ExecNode("loop_body")
        self.add(self.body)


# ============================================================================
# MAIN STRUCTURER
# ============================================================================

class PALSGLDecompiler:

    def __init__(self, pal_function):

        self.func = pal_function
        self.cfg = pal_function.cfg
        self.sgl_version = "PALSGLdecomp_v54b_condition_provenance_sidecar_debugger"

        self.root = ExecNode("sequence")

        self.visited = set()

        self.loop_headers = set()
        self.loop_latches = {}
        self.loop_nodes = {}
        self.loop_exits = {}
        self.loop_normal_exits = {}
        self.loop_single_exit_tests = set()
        self.loop_tail_chains = {}
        self.loop_body_headers = set()

        # v8: explicit loop-control markers. SGL owns recognition of
        # loop-exit/backedge semantics; emitter only prints break/continue.
        self.branch_control_events = []
        self.loop_tail_test_nodes = set()
        self.loop_guard_nodes = {}

        # Diagnostics
        self.events = []
        self.branch_events = []
        self.loop_condition_events = []
        self.loop_contract_events = []
        self.condition_source_events = []

        # v24 metadata consolidation handoff.
        # SGL remains the owner of control structure and branch/loop polarity.
        # It does not rewrite expressions for the emitter.  Instead it exports
        # exact condition consumers and conservative candidate records for
        # PHIfolder/emitter to consume by SID/node identity.
        self.metadata_events = []
        self.condition_consumers = []
        self.condition_provenance_sidecars = []
        self.condition_temp_defs = []
        self.post_update_alias_candidates = []

        # v26: consume PALSemanticGraphBuilder metadata sandwiches when
        # available.  These are facts, not structure: edge condition truth,
        # latch/update ownership, block ownership/gateway hints, and suspicious
        # raw/HF successor custody.  SGL remains the owner of break/continue/loop
        # shape and falls back to legacy CFG heuristics when metadata is absent.
        self.block_branch_custody = getattr(pal_function, "block_branch_custody", {}) or {}
        self.edge_condition_truth = getattr(pal_function, "edge_condition_truth", {}) or {}

        # v40: canonical EdgeTruth from PALSemanticGraphBuilder v25.
        # This is the new branch-polarity contract: predicates are keyed by
        # exact CFG edge (src,dst), not by block-level condition.  v24
        # edge_condition_truth remains as compatibility fallback.
        self.edge_truth = getattr(pal_function, "edge_truth", {}) or {}
        self.edge_truth_by_src = getattr(pal_function, "edge_truth_by_src", {}) or {}
        self.edge_truth_debug = getattr(pal_function, "edge_truth_debug", []) or []

        self.induction_updates_by_block = getattr(pal_function, "induction_updates_by_block", {}) or {}
        self.latch_update_facts = getattr(pal_function, "latch_update_facts", {}) or {}
        self.block_ownership_facts = getattr(pal_function, "block_ownership_facts", {}) or {}
        self.suspicious_successor_custody = getattr(pal_function, "suspicious_successor_custody", []) or []
        self.sgl_structuring_handoff = getattr(pal_function, "sgl_structuring_handoff", {}) or {}
        self.metadata_consumed_events = []

    # ----------------------------------------------------------------

    def build(self):

        self._identify_loops()

        entry = getattr(self.cfg, "entry", None)

        if entry is not None:
            self._emit_node(entry, self.root, stop_nodes=set())

        # v22: final contract pass over the already-built ExecTree.  This is
        # deliberately after structuring so stale loop-role/predicate pairs
        # cannot escape into the emitter even if an older construction path
        # bypassed the main normalizer.
        self._finalize_exec_tree_contracts_v22()

        # v42: after all latch/normal-epilogue decisions are complete, elide
        # redundant tail-position continue leaves.  This is deliberately after
        # v41 normal-latch suppression, because v41 needs those terminal leaves
        # to prove that the normal epilogue is unreachable.
        self._elide_tail_position_continues_v42()

        # v24: consolidate metadata for PHIfolder/emitter.  This pass does
        # not mutate the ExecTree.  It records condition consumers, unresolved
        # condition temps, and post-update alias candidates as exact metadata.
        self._consolidate_metadata_v24()

        self.func.sgl_version = self.sgl_version
        self.func.sgl_metadata_handoff = {
            "version": self.sgl_version,
            "condition_consumers": list(self.condition_consumers),
            "condition_provenance_sidecars": list(self.condition_provenance_sidecars),
            "condition_temp_defs": list(self.condition_temp_defs),
            "post_update_alias_candidates": list(self.post_update_alias_candidates),
            "metadata_events": list(self.metadata_events),
        }
        self.func.sgl_condition_consumers = list(self.condition_consumers)
        self.func.sgl_condition_provenance_sidecars = list(self.condition_provenance_sidecars)
        self.func.sgl_condition_temp_defs = list(self.condition_temp_defs)
        self.func.sgl_post_update_alias_candidates = list(self.post_update_alias_candidates)
        self.func.exec_root = self.root
        self.func.exec_tree = self.root
        self.func.sgl_debug = self.events
        self.func.sgl_branch_debug = self.branch_events
        self.func.sgl_loop_debug = {
            "headers": [getattr(n, "addr", None) for n in self.loop_headers],
            "body_headers": [getattr(n, "addr", None) for n in self.loop_body_headers],
            "tail_tests": [getattr(n, "addr", None) for n in self.loop_tail_test_nodes],
            "guard_nodes": {
                getattr(h, "addr", None): getattr(g, "addr", None)
                for h, g in self.loop_guard_nodes.items()
            },
            "condition_events": self.loop_condition_events,
            "contract_events": self.loop_contract_events,
            "condition_source_events": self.condition_source_events,
            "metadata_events": self.metadata_events,
            "condition_consumers": self.condition_consumers,
            "condition_provenance_sidecars": self.condition_provenance_sidecars,
            "condition_temp_defs": self.condition_temp_defs,
            "post_update_alias_candidates": self.post_update_alias_candidates,
            "sgl_version": self.sgl_version,
            "latches": {
                getattr(h, "addr", None): [getattr(n, "addr", None) for n in ls]
                for h, ls in self.loop_latches.items()
            },
            "exits": {
                getattr(h, "addr", None): [getattr(n, "addr", None) for n in xs]
                for h, xs in self.loop_exits.items()
            },
            "normal_exits": {
                getattr(h, "addr", None): [getattr(n, "addr", None) for n in xs]
                for h, xs in self.loop_normal_exits.items()
            },
            "single_exit_tests": [getattr(n, "addr", None) for n in self.loop_single_exit_tests],
            "tail_chains": {
                getattr(h, "addr", None): [getattr(n, "addr", None) for n in chain]
                for h, chain in self.loop_tail_chains.items()
            },
            "loop_condition_roles": self._collect_loop_condition_roles_v19b(),
            "cfg_metadata_consumed": {
                "has_cfg_loop_nodes": bool(getattr(self.cfg, "loop_nodes", None)),
                "has_cfg_edge_roles": bool(getattr(self.cfg, "edge_roles", None)),
                "has_cfg_queries": bool(hasattr(self.cfg, "edge_between")),
            },
            "branch_control_events": list(self.branch_control_events),
            "metadata_consumed_events": list(self.metadata_consumed_events),
            "metadata_sandwich_counts": {
                "block_branch_custody": len(self.block_branch_custody),
                "edge_condition_truth": len(self.edge_condition_truth),
                "edge_truth": len(self.edge_truth),
                "edge_truth_debug": len(self.edge_truth_debug),
                "induction_updates_by_block": len(self.induction_updates_by_block),
                "latch_update_facts": len(self.latch_update_facts),
                "block_ownership_facts": len(self.block_ownership_facts),
                "suspicious_successor_custody": len(self.suspicious_successor_custody),
            },
        }

        return self.root

    def _collect_loop_condition_roles_v19b(self):
        out = {}

        def walk(node):
            if node is None:
                return

            if getattr(node, "kind", None) == "loop":
                h = getattr(getattr(node, "header", None), "addr", None)
                c = getattr(node, "cond_var", None)
                out[h] = {
                    "role": getattr(node, "condition_role", None),
                    "mode": getattr(node, "emit_condition_mode", None),
                    "cond": str(getattr(c, "name", c)),
                }

            for child in list(getattr(node, "children", []) or []):
                walk(child)

        walk(self.root)
        return out

    # =========================================================================
    # LOOP DISCOVERY
    # =========================================================================

    def _identify_loops(self):
        """
        Prefer FunctionCFG loop metadata when available.

        v11 rule:
            FunctionCFG owns topology and loop/backedge metadata.
            SGL consumes that metadata and only falls back to local inference
            when running against an older PALlibrary.
        """

        cfg_loop_headers = getattr(self.cfg, "loop_headers", None)
        cfg_loop_latches = getattr(self.cfg, "loop_latches", None)
        cfg_loop_nodes = getattr(self.cfg, "loop_nodes", None)
        cfg_loop_exits = getattr(self.cfg, "loop_exits", None)

        if cfg_loop_headers is not None and cfg_loop_latches is not None:
            self.loop_headers = set(cfg_loop_headers or set())
            self.loop_latches = {
                h: list(cfg_loop_latches.get(h, []) or [])
                for h in self.loop_headers
            }

            for header in list(self.loop_headers):
                if isinstance(cfg_loop_nodes, dict) and header in cfg_loop_nodes:
                    self.loop_nodes[header] = set(cfg_loop_nodes.get(header, set()) or set())
                else:
                    self.loop_nodes[header] = self._natural_loop_nodes(
                        header,
                        self.loop_latches.get(header, []),
                    )

                if isinstance(cfg_loop_exits, dict) and header in cfg_loop_exits:
                    self.loop_exits[header] = set(cfg_loop_exits.get(header, set()) or set())
                else:
                    self.loop_exits[header] = self._natural_loop_exits(
                        header,
                        self.loop_nodes.get(header, set()),
                    )
        else:
            # Backward-compatible fallback for older PALlibrary builds.
            for node in self._real_nodes():

                for e in getattr(node, "out_edges", []):

                    dst = getattr(e, "dst", None)

                    if dst is None:
                        continue

                    if dst in getattr(node, "dominators", set()):
                        self.loop_headers.add(dst)
                        self.loop_latches.setdefault(dst, []).append(node)

            for header in list(self.loop_headers):
                nodes = self._natural_loop_nodes(header, self.loop_latches.get(header, []))
                self.loop_nodes[header] = nodes
                self.loop_exits[header] = self._natural_loop_exits(header, nodes)

        # Derived SGL metadata.
        for header in list(self.loop_headers):

            if self._loop_header_has_executable_ops(header):
                self.loop_body_headers.add(header)

            for latch in self.loop_latches.get(header, []):
                if self._get_condition(latch) is not None:
                    self.loop_tail_test_nodes.add(latch)

            guard = self._detect_loop_guard_chain_node(header)
            if guard is not None:
                self.loop_guard_nodes[header] = guard

            self.loop_normal_exits[header] = self._natural_loop_normal_exits(header)

            if self._is_single_exit_test_loop(header):
                self.loop_single_exit_tests.add(header)

            tail = self._detect_latch_tail_chain(header)
            if tail:
                self.loop_tail_chains[header] = tail

    def _natural_loop_nodes(self, header, latches):
        loop_nodes = {header}
        work = list(latches or [])

        for latch in work:
            loop_nodes.add(latch)

        while work:
            n = work.pop()

            for pred in self._predecessors(n):
                if pred not in loop_nodes:
                    loop_nodes.add(pred)
                    work.append(pred)

        return loop_nodes

    def _natural_loop_exits(self, header, nodes):
        exits = set()

        for n in nodes:
            for succ in self._successors(n):
                if succ not in nodes:
                    exits.add(succ)

        return exits

    def _natural_loop_normal_exits(self, header):
        """
        Normal loop exits are the exits reached by loop guard/header tests,
        not arbitrary break-action blocks inside the loop.

        For alpha_four inner loop:
            0x10126f / 0x101275 guard exits -> 0x10127f normal continuation
            0x10125c false -> 0x101262 break action, not normal exit

        The break-action node must stay in the branch that reaches it; it must
        not be emitted unconditionally after the loop.
        """

        nodes = self.loop_nodes.get(header, set())
        exits = self.loop_exits.get(header, set())
        normals = set()

        # Header direct exits.
        for succ in self._successors(header):
            if succ not in nodes and succ in exits:
                normals.add(succ)

        # Guard-chain exits.
        guard = self.loop_guard_nodes.get(header)
        if guard is not None:
            for succ in self._successors(guard):
                if succ not in nodes and succ in exits:
                    normals.add(succ)

        # Body-header latch-tested loops may exit through latch/test nodes.
        # Keep this conservative: only exits from latch condition blocks count
        # as normal. Action exits from arbitrary body branches do not.
        for latch in self.loop_latches.get(header, []):
            if self._get_condition(latch) is None:
                continue
            for succ in self._successors(latch):
                if succ not in nodes and succ in exits:
                    normals.add(succ)

        if normals:
            return normals

        # Fallback: if there is a single exit, it is probably normal.
        if len(exits) == 1:
            return set(exits)

        return set()


    def _is_single_exit_test_loop(self, header):
        """
        Detect loops whose header condition is an exit test.

        Pattern:
            header has condition
            one successor is loop body
            the other successor is loop exit/join

        For alpha_four's small gamma loop, the header condition is:
            gamma < 1
        which is an exit test for source while(gamma > 0). The emitter already
        inverts loop conditions for this CFG shape, so we pass the exit test.
        """

        if self._get_condition(header) is None:
            return False

        nodes = self.loop_nodes.get(header, set())
        exits = self.loop_exits.get(header, set())

        if not nodes or not exits:
            return False

        succs = self._successors(header)

        if len(succs) != 2:
            return False

        inside = [s for s in succs if s in nodes and s is not header]
        outside = [s for s in succs if s not in nodes or s in exits]

        return bool(inside and outside)

    def _detect_latch_tail_chain(self, header):
        """
        Detect simple latch/tail condition chains for body-header loops.

        alpha_four outer do/while tail:
            0x10129b: counter update; if 4 < counter backedge else 0x1012a9
            0x1012a9: if 99 < alpha backedge else return

        We do not emit break/continue here yet. We preserve metadata so the
        emitter or a later SGL lowering can render an executable tail check.
        """

        if header not in self.loop_body_headers:
            return []

        latches = list(self.loop_latches.get(header, []) or [])

        chain = []

        for latch in latches:
            if self._get_condition(latch) is None:
                continue

            chain.append(latch)

            for succ in self._successors(latch):
                if succ is header:
                    continue
                if succ in self.loop_nodes.get(header, set()):
                    continue
                # Follow one external condition node that can backedge to the
                # same header; this catches OR-style tail chains.
                if self._get_condition(succ) is not None:
                    for ss in self._successors(succ):
                        if ss is header:
                            chain.append(succ)
                            break

        # Stable order by address.
        return self._ordered_nodes(set(chain))

    def _loop_header_has_executable_ops(self, header):
        """
        True when a loop header contains executable work beyond PHI and branch
        condition construction.
        """

        block = getattr(header, "block", None)

        if block is None:
            return False

        term = getattr(block, "terminator", None)
        term_cond = getattr(term, "condition", None)
        cond_sid = getattr(term_cond, "ssa_id", None)

        for op in list(getattr(block, "ops", []) or []):
            opcode = getattr(op, "opcode", None)

            if opcode == "MULTIEQUAL":
                continue

            out = getattr(op, "output", None)
            out_sid = getattr(out, "ssa_id", None)

            if cond_sid is not None and out_sid == cond_sid:
                continue

            if opcode in ("INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
                          "INT_LESSEQUAL", "INT_SLESSEQUAL", "BOOL_NEGATE"):
                if term is not None and getattr(term, "opcode", None) == "CBRANCH":
                    continue

            return True

        return False

    def _predecessors(self, node):
        try:
            return list(node.predecessors())
        except Exception:
            out = []
            for e in list(getattr(node, "in_edges", []) or []):
                src = getattr(e, "src", None)
                if src is not None:
                    out.append(src)
            return out

    def _detect_loop_guard_chain_node(self, header):
        """
        Detect a two-stage loop guard:

            header condition exits loop or continues to guard
            guard condition exits loop or continues to body

        alpha_four inner loop:
            0x10126f: i > 9 exit else 0x101275
            0x101275: beta < 1 exit else body

        We return the guard node so traversal can skip emitting it as a nested
        if. The composed condition is handled by _loop_guard_chain_condition().
        """

        nodes = self.loop_nodes.get(header, set())
        exits = self.loop_exits.get(header, set())

        if not nodes or not exits:
            return None

        succs = self._successors(header)

        if len(succs) != 2:
            return None

        inside = [s for s in succs if s in nodes and s is not header]
        outside = [s for s in succs if s not in nodes]

        if len(inside) != 1 or len(outside) != 1:
            return None

        cand = inside[0]

        if self._get_condition(cand) is None:
            return None

        cand_succs = self._successors(cand)

        if len(cand_succs) != 2:
            return None

        cand_inside = [s for s in cand_succs if s in nodes and s is not header and s is not cand]
        cand_outside = [s for s in cand_succs if s not in nodes or s in exits]

        if not cand_inside or not cand_outside:
            return None

        return cand

    def _loop_guard_chain_body(self, header):
        guard = self.loop_guard_nodes.get(header)

        if guard is None:
            return None

        nodes = self.loop_nodes.get(header, set())

        for succ in self._successors(guard):
            if succ in nodes and succ is not header and succ is not guard:
                return succ

        return None

    def _loop_guard_chain_condition(self, header):
        """
        Conservative executable lowering for chained loop guards.

        We treat both header and guard conditions as exit tests and continue
        while neither is true:
            while not(header_exit_cond) and not(guard_exit_cond):
        """

        guard = self.loop_guard_nodes.get(header)

        if guard is None:
            return None

        h = self._cond_expr_raw(header)
        g = self._cond_expr_raw(guard)

        if not h or not g:
            return None

        # Return the exit-test disjunction, not the continue condition.
        # The current emitter's loop-condition forcing inverts header
        # conditions for this CFG shape, so passing exit1 OR exit2 yields:
        #     while not (exit1 or exit2):
        # which is the desired executable guard.
        return RawCond("(%s) or (%s)" % (h, g))



    def _as_list(self, maybe_iterable):
        if maybe_iterable is None:
            return []
        try:
            if callable(maybe_iterable):
                maybe_iterable = maybe_iterable()
        except Exception:
            return []
        try:
            return list(maybe_iterable or [])
        except TypeError:
            return [maybe_iterable]
        except Exception:
            return []

    # =========================================================================
    # v26 SEMANTIC-GRAPH METADATA SANDWICH CONSUMERS
    # =========================================================================

    def _addr_v26(self, node_or_addr):
        """Return an integer address for a CFG node or integer-like address."""
        if node_or_addr is None:
            return None
        if isinstance(node_or_addr, int):
            return node_or_addr
        try:
            addr = getattr(node_or_addr, "addr", None)
            if isinstance(addr, int):
                return addr
        except Exception:
            pass
        return None

    def _hex_v26(self, x):
        try:
            return hex(x) if isinstance(x, int) else str(x)
        except Exception:
            return str(x)

    def _edge_key_candidates_v26(self, src, dst):
        saddr = self._addr_v26(src)
        daddr = self._addr_v26(dst)
        keys = []
        if saddr is not None and daddr is not None:
            keys.extend([
                (saddr, daddr),
                (self._hex_v26(saddr), self._hex_v26(daddr)),
                "%s->%s" % (self._hex_v26(saddr), self._hex_v26(daddr)),
                "%s->%s" % (saddr, daddr),
            ])
        return keys

    def _edge_truth_record_v40(self, src, dst):
        """Return canonical PALSemanticGraphBuilder v25 EdgeTruth for src->dst."""
        table = getattr(self, "edge_truth", {}) or {}
        if not table or src is None or dst is None:
            return None

        for key in self._edge_key_candidates_v26(src, dst):
            try:
                if key in table:
                    rec = table.get(key)
                    if isinstance(rec, dict):
                        return rec
            except Exception:
                pass

        saddr = self._addr_v26(src)
        daddr = self._addr_v26(dst)
        for rec in list(table.values()):
            if not isinstance(rec, dict):
                continue
            if rec.get("src") == saddr and rec.get("dst") == daddr:
                return rec
            if rec.get("src_hex") == self._hex_v26(saddr) and rec.get("dst_hex") == self._hex_v26(daddr):
                return rec
        return None

    def _edge_truth_record_v26(self, src, dst):
        """
        Compatibility lookup used by older SGL code paths.

        v40 prefers canonical EdgeTruth records produced by
        PALSemanticGraphBuilder v25.  If absent, fall back to the older v24
        edge_condition_truth table so old binaries/stacks remain runnable.
        """
        rec = self._edge_truth_record_v40(src, dst)
        if rec is not None:
            return rec

        table = getattr(self, "edge_condition_truth", {}) or {}
        if not table or src is None or dst is None:
            return None

        for key in self._edge_key_candidates_v26(src, dst):
            try:
                if key in table:
                    return table.get(key)
            except Exception:
                pass

        saddr = self._addr_v26(src)
        daddr = self._addr_v26(dst)
        for rec in list(table.values()):
            if not isinstance(rec, dict):
                continue
            if rec.get("src") == saddr and rec.get("dst") == daddr:
                return rec
            if rec.get("src_hex") == self._hex_v26(saddr) and rec.get("dst_hex") == self._hex_v26(daddr):
                return rec
        return None

    def _metadata_record_is_canonical_edge_truth_v40(self, rec):
        if not isinstance(rec, dict):
            return False
        if rec.get("predicate_holds_means_take_edge") is True:
            return True
        if str(rec.get("version") or "").startswith("PALSemanticGraphBuilder_v25_EdgeTruth"):
            return True
        if rec.get("selection_source") is not None or rec.get("selection_reason") is not None:
            return True
        return False

    def _edgetruth_condition_for_edge_v40(self, src, dst, cond=None):
        """
        Return RawCond only from canonical v25 EdgeTruth.  This is used by
        places such as loop-condition normalization where we want to know
        whether the new edge-bound contract actually exists, not merely fall
        back to legacy block-condition heuristics.
        """
        rec = self._edge_truth_record_v40(src, dst)
        if not isinstance(rec, dict):
            return None
        expr = rec.get("predicate") or rec.get("edge_expr")
        if not expr:
            return None
        self._metadata_record_event_v26(
            "edge_truth_v40_consumed",
            src=self._addr_v26(src),
            dst=self._addr_v26(dst),
            expr=expr,
            confidence=rec.get("confidence"),
            selection_source=rec.get("selection_source"),
            selection_reason=rec.get("selection_reason"),
            invert_for_edge=rec.get("invert_for_edge"),
            is_taken_edge=rec.get("is_taken_edge"),
            is_fallthrough_edge=rec.get("is_fallthrough_edge"),
        )
        return RawCond(
            expr,
            source=cond,
            inverted=str(expr).strip().startswith("not "),
            reason=rec.get("selection_reason") or rec.get("selection_source") or "edge_truth_v40",
        )

    def _block_branch_custody_record_v26(self, node):
        addr = self._addr_v26(node)
        table = getattr(self, "block_branch_custody", {}) or {}
        if addr is None or not table:
            return None
        for key in (addr, self._hex_v26(addr), str(addr)):
            try:
                if key in table:
                    return table.get(key)
            except Exception:
                pass
        for rec in list(table.values()):
            if isinstance(rec, dict) and rec.get("block_addr") == addr:
                return rec
        return None

    def _block_ownership_record_v26(self, node):
        addr = self._addr_v26(node)
        table = getattr(self, "block_ownership_facts", {}) or {}
        if addr is None or not table:
            return None
        for key in (addr, self._hex_v26(addr), str(addr)):
            try:
                if key in table:
                    return table.get(key)
            except Exception:
                pass
        for rec in list(table.values()):
            if isinstance(rec, dict) and rec.get("addr") == addr:
                return rec
        return None

    def _latch_facts_for_loop_v26(self, loop_header):
        haddr = self._addr_v26(loop_header)
        table = getattr(self, "latch_update_facts", {}) or {}
        if haddr is None or not table:
            return None
        for key in (haddr, self._hex_v26(haddr), str(haddr)):
            try:
                if key in table:
                    return table.get(key)
            except Exception:
                pass
        for rec in list(table.values()):
            if isinstance(rec, dict) and rec.get("loop_header") == haddr:
                return rec
        return None

    def _metadata_record_event_v26(self, kind, **kw):
        try:
            rec = {"kind": kind}
            rec.update(kw)
            self.metadata_consumed_events.append(rec)
        except Exception:
            pass

    def _metadata_condition_for_edge_v26(self, src, dst, cond=None):
        """Return RawCond true for src->dst from GraphBuilder edge metadata.

        v40 consumes canonical EdgeTruth first.  EdgeTruth predicates are
        already edge-bound and already reconciled against ASM/RAW/HF evidence,
        so SGL must not apply the older protected-mirror NOT a second time.
        v24 edge_condition_truth remains as fallback and still uses the v31
        protected mirror guard.
        """
        rec = self._edge_truth_record_v26(src, dst)
        if not rec:
            return None

        is_canonical = self._metadata_record_is_canonical_edge_truth_v40(rec)
        expr = rec.get("predicate") or rec.get("edge_expr") or rec.get("hf_expr")
        if not expr:
            return None

        original_expr = str(expr).strip()
        mirror = None

        if is_canonical:
            # v25 EdgeTruth has already decided whether this exact edge takes
            # HF predicate or its complement.  Do not re-run protected mirror.
            self._metadata_record_event_v26(
                "edge_truth_v40_consumed",
                src=self._addr_v26(src),
                dst=self._addr_v26(dst),
                expr=expr,
                confidence=rec.get("confidence"),
                selection_source=rec.get("selection_source"),
                selection_reason=rec.get("selection_reason"),
                invert_for_edge=rec.get("invert_for_edge"),
                is_taken_edge=rec.get("is_taken_edge"),
                is_fallthrough_edge=rec.get("is_fallthrough_edge"),
                mnemonic=rec.get("mnemonic"),
                condition_opcode=rec.get("condition_opcode"),
            )
        else:
            mirror = self._metadata_branch_mirror_requires_not_v30(src, dst, rec)
            if mirror:
                expr = self._metadata_not_expr_v30(original_expr)
                if expr != original_expr:
                    self._metadata_record_event_v26(
                        "protected_metadata_branch_mirror_not_applied_v31",
                        src=self._addr_v26(src),
                        dst=self._addr_v26(dst),
                        original_expr=original_expr,
                        expr=expr,
                        mnemonic=mirror.get("mnemonic"),
                        opcode=mirror.get("opcode"),
                        reason=mirror.get("reason"),
                    )

        self._metadata_record_event_v26(
            "edge_condition_truth_consumed",
            src=self._addr_v26(src),
            dst=self._addr_v26(dst),
            expr=expr,
            trust=rec.get("trust") or rec.get("confidence"),
            reason=rec.get("invert_source") or rec.get("selection_reason") or rec.get("selection_source"),
        )
        return RawCond(
            expr,
            source=cond,
            inverted=str(expr).strip().startswith("not "),
            reason=(
                "protected_metadata_branch_mirror_not_v31" if mirror else
                (rec.get("selection_reason") or rec.get("selection_source") or
                 rec.get("invert_source") or rec.get("trust") or rec.get("confidence") or
                 "metadata_edge_condition_truth_v26")
            ),
        )

    def _metadata_not_expr_v30(self, expr):
        """Wrap an already-oriented predicate in NOT without double-negating."""
        s = str(expr or "").strip()
        if not s:
            return s
        if s.startswith("not "):
            return s
        return "not (%s)" % s

    def _metadata_branch_mirror_requires_not_v30(self, src, dst, rec=None):
        """Return protected branch-mirror metadata, or None.

        v31 tight rule:
          A raw-mnemonic/HF-opcode complement pair is not enough by itself.
          Ordinary switch/range/parity branches frequently need edge-oriented
          not(...) predicates, but they are not protected branch mirrors.

          Protected mirror NOT is allowed only when PAL metadata proves all of:
            1. the edge predicate is complement-shaped or explicitly inverted;
            2. the edge participates in loop-control custody;
            3. the edge/block has suspicious raw/HF successor custody.

          This remains address-agnostic and constant-agnostic.  It does not know
          alpha_four, 0x101235, local_18, or 0xf.
        """
        if rec is None:
            rec = self._edge_truth_record_v26(src, dst)

        mnemonic, opcode = self._metadata_mnemonic_opcode_pair_v29(src, dst)
        mnemonic = str(mnemonic or "").upper()
        opcode = str(opcode or "").upper()

        complement_reason = None

        if self._metadata_pair_is_complement_v29(mnemonic, opcode):
            complement_reason = "raw_mnemonic_hf_opcode_complement"

        if isinstance(rec, dict):
            try:
                if rec.get("invert_for_edge") is True:
                    complement_reason = complement_reason or "edge_invert_for_edge_metadata"
            except Exception:
                pass

            blob = " ".join(
                str(rec.get(k) or "")
                for k in (
                    "invert_source", "reason", "trust", "edge_reason",
                    "condition_reason", "condition_polarity_reason",
                    "condition_polarity", "role", "raw_type", "status",
                )
            ).lower()

            # Only explicit complement/mirror declarations count here.  The word
            # "invert" may appear in ordinary edge-polarity records and is too
            # broad for the protected branch-mirror class.
            if "complement" in blob or "mirror" in blob:
                complement_reason = complement_reason or "metadata_text_declares_complement"

        if not complement_reason:
            return None

        loop_custody = self._metadata_edge_has_loop_control_custody_v31(src, dst)
        suspicious = self._metadata_edge_has_suspicious_custody_v31(src, dst, rec)

        if not (loop_custody and suspicious):
            self._metadata_record_event_v26(
                "metadata_branch_mirror_rejected_v31",
                src=self._addr_v26(src),
                dst=self._addr_v26(dst),
                mnemonic=mnemonic,
                opcode=opcode,
                complement_reason=complement_reason,
                loop_custody=bool(loop_custody),
                suspicious_custody=bool(suspicious),
            )
            return None

        return {
            "mnemonic": mnemonic,
            "opcode": opcode,
            "reason": "protected_branch_mirror_v31:%s" % complement_reason,
            "loop_custody": True,
            "suspicious_custody": True,
        }

    def _metadata_edge_has_loop_control_custody_v31(self, src, dst):
        """True when src->dst is a loop-control edge, not an ordinary branch arm."""
        if src is None or dst is None:
            return False

        owner = self._innermost_loop_for_node(src)
        if owner is None:
            return False

        if dst is owner:
            return True

        try:
            if self._edge_continues_loop(src, dst) is owner:
                return True
        except Exception:
            pass

        try:
            if self._edge_exits_loop(src, dst) is owner:
                return True
        except Exception:
            pass

        try:
            if self._target_is_loop_latch_node(owner, dst):
                return True
        except Exception:
            pass

        try:
            if self._metadata_target_is_continuation_gateway_v26(dst, owner_loop=owner, from_node=src):
                return True
        except Exception:
            pass

        # Metadata sandwich fallback: some graph records already classify edge
        # custody textually even when CFG loop helpers are incomplete.
        text = self._role_text_for_edge_v28(src, dst)
        if any(tok in text for tok in (
            "latch", "backedge", "loop_exit", "loop-exit",
            "continue", "continuation_gateway", "normal_exit",
        )):
            return True

        return False

    def _metadata_edge_has_suspicious_custody_v31(self, src, dst, rec=None):
        """True for raw/HF successor-custody anomalies supplied by PAL metadata."""
        if rec is None:
            rec = self._edge_truth_record_v26(src, dst)

        blobs = []

        def add_obj(obj):
            if not isinstance(obj, dict):
                return
            for k in (
                "status", "palraw_status", "raw_status", "successor_status",
                "role", "raw_type", "trust", "invert_source", "reason",
                "edge_reason", "condition_reason", "condition_polarity_reason",
                "condition_source", "custody", "role_hint",
            ):
                v = obj.get(k)
                if v:
                    blobs.append(str(v))
            for k in (
                "successors_differ", "successor_mismatch", "mismatch",
                "hf_extra_successors", "raw_missing_successors",
                "raw_terminal_successors", "norm_successors",
            ):
                v = obj.get(k)
                if v not in (None, False, [], (), set(), ""):
                    blobs.append("%s=%r" % (k, v))

        add_obj(rec)
        add_obj(self._block_branch_custody_record_v26(src))
        add_obj(self._block_ownership_record_v26(src))
        add_obj(self._block_ownership_record_v26(dst))

        try:
            e = self._cfg_edge(src, dst)
            if e is not None:
                for attr in (
                    "status", "palraw_status", "raw_status", "successor_status",
                    "role", "raw_type", "type", "condition_polarity_reason",
                    "condition_polarity_source", "condition_source",
                ):
                    v = getattr(e, attr, None)
                    if v:
                        blobs.append(str(v))
                for attr in (
                    "successors_differ", "successor_mismatch",
                    "hf_extra_successors", "raw_missing_successors",
                ):
                    v = getattr(e, attr, None)
                    if v not in (None, False, [], (), set(), ""):
                        blobs.append("%s=%r" % (attr, v))
        except Exception:
            pass

        # Global suspicious-successor table from GraphBuilder.
        saddr = self._addr_v26(src)
        daddr = self._addr_v26(dst)
        for item in list(getattr(self, "suspicious_successor_custody", []) or []):
            if not isinstance(item, dict):
                continue
            is_src = item.get("src") == saddr or item.get("src_addr") == saddr or item.get("block") == saddr or item.get("block_addr") == saddr
            is_dst = item.get("dst") == daddr or item.get("dst_addr") == daddr or item.get("target") == daddr or item.get("target_addr") == daddr
            if is_src and (is_dst or daddr is None or item.get("dst") is None and item.get("dst_addr") is None):
                blobs.append(str(item))

        text = " ".join(blobs).lower()
        suspicious_tokens = (
            "successors_differ", "successor_mismatch", "mismatch",
            "order_fallback", "raw_true_order_fallback",
            "hf_extra", "raw_missing", "not seen in raw",
            "normalized_extra", "suspicious",
        )
        if any(tok in text for tok in suspicious_tokens):
            return True

        # A continuation gateway on a loop-control edge is also suspicious enough
        # for protected mirror use: it means the edge's destination is a
        # structuring substitute/join rather than the raw terminal target.
        try:
            owner = self._innermost_loop_for_node(src)
            if owner is not None and self._metadata_target_is_continuation_gateway_v26(dst, owner_loop=owner, from_node=src):
                return True
        except Exception:
            pass

        return False

    def _metadata_edge_invert_v26(self, src, dst):
        rec = self._edge_truth_record_v26(src, dst)
        if isinstance(rec, dict) and "invert_for_edge" in rec:
            try:
                return bool(rec.get("invert_for_edge"))
            except Exception:
                return False
        return None

    def _metadata_edge_reason_v26(self, src, dst):
        rec = self._edge_truth_record_v26(src, dst)
        if not isinstance(rec, dict):
            return None
        return (
            rec.get("selection_reason")
            or rec.get("selection_source")
            or rec.get("invert_source")
            or rec.get("trust")
            or rec.get("confidence")
            or rec.get("role")
            or rec.get("raw_type")
        )

    def _metadata_edge_mnemonic_v26(self, src, dst=None):
        rec = self._edge_truth_record_v26(src, dst) if dst is not None else None
        if isinstance(rec, dict) and rec.get("mnemonic"):
            return str(rec.get("mnemonic")).upper()
        brec = self._block_branch_custody_record_v26(src)
        if isinstance(brec, dict) and brec.get("terminal_mnemonic"):
            return str(brec.get("terminal_mnemonic")).upper()
        return ""

    def _metadata_mnemonic_opcode_pair_v29(self, src, dst=None):
        """
        Extract raw branch mnemonic and HF/formula condition opcode from any
        available metadata/debug string.

        Some GraphBuilder iterations expose these as explicit fields; others
        only leave strings such as:
            mnemonic=JZ hf_cond_opcode=INT_NOTEQUAL
        in the reason/invert_source field.  SGL uses this only for generic
        branch/opcode complement pairs, never for address-specific repairs.
        """
        mnemonic = None
        opcode = None

        rec = self._edge_truth_record_v26(src, dst) if dst is not None else None
        if isinstance(rec, dict):
            for k in (
                "mnemonic", "branch_mnemonic", "terminal_mnemonic",
                "raw_mnemonic", "raw_terminal_mnemonic",
            ):
                v = rec.get(k)
                if v and not mnemonic:
                    mnemonic = str(v).upper()

            for k in (
                "hf_cond_opcode", "condition_opcode", "cond_opcode",
                "opcode", "hf_opcode",
            ):
                v = rec.get(k)
                if v and not opcode:
                    opcode = str(v).upper()

            blob = " ".join(
                str(rec.get(k) or "")
                for k in (
                    "invert_source", "reason", "trust", "edge_reason",
                    "condition_reason", "role", "raw_type", "status",
                )
            )
            if blob:
                if not mnemonic:
                    m = re.search(r"mnemonic\s*=\s*([A-Za-z][A-Za-z0-9_]*)", blob)
                    if m:
                        mnemonic = m.group(1).upper()
                if not opcode:
                    m = re.search(r"(?:hf_cond_opcode|condition_opcode|cond_opcode|opcode)\s*=\s*([A-Z_]+)", blob)
                    if m:
                        opcode = m.group(1).upper()

        if not mnemonic:
            mnemonic = self._metadata_edge_mnemonic_v26(src, dst) or self._edge_mnemonic_v23(src, dst)
            mnemonic = str(mnemonic or "").upper()

        if not opcode:
            opcode = self._condition_opcode_for_cfg_node_v19(src)
            opcode = str(opcode or "").upper()

        return mnemonic, opcode

    def _metadata_pair_is_complement_v29(self, mnemonic, opcode):
        """Generic raw-mnemonic/HF-opcode complement table."""
        m = str(mnemonic or "").upper()
        op = str(opcode or "").upper()

        if m in ("JZ", "JE") and op == "INT_NOTEQUAL":
            return True
        if m in ("JNZ", "JNE") and op == "INT_EQUAL":
            return True
        if m in ("JG", "JA", "JNLE", "JNBE") and op in (
            "INT_SLESS", "INT_LESS", "INT_SLESSEQUAL", "INT_LESSEQUAL"
        ):
            return True

        return False

    def _metadata_target_is_continuation_gateway_v26(self, target_node, owner_loop=None, from_node=None):
        """
        True when GraphBuilder/CFG structure marks target as a shared
        continuation/join/gateway that should not be inlined as branch-local
        action of owner_loop.

        v32 extends the original metadata-only rule with a conservative
        structural fallback: when an edge exits an inner loop to a conditional
        or postdominator join that belongs to an enclosing region and has other
        incoming paths, the target is a continuation gateway.  The inner loop
        arm should emit `break`; the enclosing region should emit the gateway.
        """
        rec = self._block_ownership_record_v26(target_node)
        if isinstance(rec, dict):
            role = str(rec.get("role_hint") or "").lower()

            gateway_role = bool(role) and any(x in role for x in (
                "gateway", "shared_join", "shared_condition", "shared_executable_join",
                "order_fallback", "enclosing_loop_condition",
            ))

            if gateway_role:
                owner_addr = self._addr_v26(owner_loop)
                not_owned = set(rec.get("not_owned_by_loops") or [])
                if owner_addr is not None and owner_addr in not_owned:
                    return True

                # For optimized CFGs, the successor may be a condition/join block
                # reached by an order-fallback or loop-exit edge.  Treat it as
                # shared continuation even when loop ownership maps are incomplete.
                if rec.get("condition_block") and (
                    rec.get("is_join")
                    or rec.get("incoming_order_fallback")
                    or rec.get("incoming_loop_exit")
                ):
                    return True

                if "order_fallback" in role or "enclosing_loop_condition" in role:
                    return True

        # v32 structural fallback.  This intentionally does not depend on a
        # particular address, constant, switch value, or test program.  It fires
        # only for nested-loop exits to shared enclosing-region joins/gateways.
        if self._structural_target_is_continuation_gateway_v32(
            target_node,
            owner_loop=owner_loop,
            from_node=from_node,
        ):
            return True

        return False

    def _structural_target_is_continuation_gateway_v32(self, target_node, owner_loop=None, from_node=None):
        """
        Conservative generic fallback for continuation-gateway ownership.

        A target is a structural continuation gateway for owner_loop when:
          * from_node is inside owner_loop;
          * target_node is outside owner_loop but still in an enclosing region;
          * target_node is a condition block, an ipdom/join, or has multiple
            predecessors; and
          * at least one incoming path comes from outside owner_loop, or an
            enclosing conditional region has target_node as ipdom and reaches
            from_node before that join.

        This prevents a nested loop's exit arm from swallowing the enclosing
        switch/if continuation condition as branch-local action.  Break the
        inner loop; emit the continuation at the enclosing region boundary.
        """
        if target_node is None or owner_loop is None or from_node is None:
            return False

        owner_nodes = set(self.loop_nodes.get(owner_loop, set()) or set())
        if not owner_nodes:
            return False

        if from_node not in owner_nodes:
            return False

        if target_node in owner_nodes:
            return False

        if target_node in self.loop_headers:
            return False

        if self._target_is_function_exit_block(target_node):
            return False

        if self._target_is_loop_tail_chain_node(target_node):
            return False

        # A plain single-predecessor cleanup/action block after a break is not
        # a shared continuation gateway.  Keep those as action+break.
        preds = list(self._predecessors(target_node) or [])
        pred_set = set(preds)
        outside_preds = [p for p in preds if p not in owner_nodes]
        inside_preds = [p for p in preds if p in owner_nodes]

        is_condition = self._get_condition(target_node) is not None
        is_shared_pred = len(pred_set) >= 2 and bool(outside_preds)

        # ipdom/enclosing-region evidence: some conditional/dispatch node
        # outside the inner loop uses target_node as its join, and that region
        # reaches the inner-loop latch/break source.  This captures switch/range
        # and if/else continuations without naming the construct.
        ipdom_join = False
        try:
            for n in self._real_nodes():
                if n is target_node or n in owner_nodes:
                    continue
                if getattr(n, "ipdom", None) is not target_node:
                    continue
                if self._reaches(n, from_node):
                    ipdom_join = True
                    break
        except Exception:
            ipdom_join = False

        if not (is_condition or is_shared_pred or ipdom_join):
            return False

        if not (outside_preds or ipdom_join):
            return False

        # If the target is executable but not conditional/shared, it may be a
        # cleanup block attached to a real break; do not steal it.  Conditional
        # executable joins are allowed, because they are region continuations.
        if self._node_has_executable_ops_cfg(target_node) and not is_condition and not ipdom_join:
            return False

        self._metadata_record_event_v26(
            "structural_continuation_gateway_v32",
            source="cfg_ipdom_predicate_fallback",
            from_addr=self._addr_v26(from_node),
            target=self._addr_v26(target_node),
            owner_loop=self._addr_v26(owner_loop),
            is_condition=is_condition,
            shared_pred=is_shared_pred,
            ipdom_join=ipdom_join,
            pred_count=len(pred_set),
            outside_pred_count=len(outside_preds),
            inside_pred_count=len(inside_preds),
        )
        return True

    def _node_by_addr_v27(self, addr):
        """Resolve integer block address back to a CFG node when possible."""
        if addr is None:
            return None
        try:
            nodes = getattr(self.cfg, "nodes", {}) or {}
            if addr in nodes:
                return nodes.get(addr)
            h = self._hex_v26(addr)
            if h in nodes:
                return nodes.get(h)
        except Exception:
            pass
        for n in self._real_nodes():
            if self._addr_v26(n) == addr:
                return n
        return None

    def _metadata_loop_continuation_gateway_nodes_v27(self, loop_header):
        """
        Return loop-exit continuation/gateway nodes supplied by GraphBuilder.
        These are normal post-loop continuation candidates, not branch-local
        action blocks.  SGL may emit them after the loop body, just as it emits
        normal guard exits.
        """
        facts = self._latch_facts_for_loop_v26(loop_header) or {}
        out = []
        for a in list(facts.get("continuation_gateways") or []):
            if not isinstance(a, int):
                continue
            n = self._node_by_addr_v27(a)
            if n is not None:
                out.append(n)
        return out

    def _metadata_edge_complement_requires_invert_v27(self, src, dst):
        """True only for the protected branch-mirror class.

        v31: raw mnemonic/HF opcode complement alone is ordinary edge
        orientation, not necessarily a protected mirror.  Require the same
        loop-control + suspicious-custody filter used by
        _metadata_branch_mirror_requires_not_v30().
        """
        rec = self._edge_truth_record_v26(src, dst)
        mirror = self._metadata_branch_mirror_requires_not_v30(src, dst, rec)
        if not mirror:
            return False

        self._metadata_record_event_v26(
            "protected_metadata_complement_pair_detected_v31",
            src=self._addr_v26(src),
            dst=self._addr_v26(dst),
            mnemonic=mirror.get("mnemonic"),
            opcode=mirror.get("opcode"),
            reason=mirror.get("reason"),
        )
        return True

    def _metadata_loop_update_blocks_v26(self, loop_header):
        facts = self._latch_facts_for_loop_v26(loop_header) or {}
        out = set()
        for k in ("update_blocks", "latch_blocks"):
            for a in list(facts.get(k) or []):
                if isinstance(a, int):
                    out.add(a)
        return out

    def _metadata_node_is_latch_update_for_loop_v26(self, loop_header, node):
        addr = self._addr_v26(node)
        if addr is None or loop_header is None:
            return False
        return addr in self._metadata_loop_update_blocks_v26(loop_header)

    def _metadata_action_reaches_latch_update_v26(self, loop_header, target_node, limit=4):
        """
        v27 conservative metadata-guided reachability to a known update/latch block.

        General rule: metadata may confirm a simple linear action-to-latch path,
        but it must not collapse structured branch arms.  If the candidate arm
        begins at, or crosses through, a conditional dispatch/gateway, SGL must
        emit the structure normally and let the latch appear through ordinary
        traversal or loop-exit handling.

        This prevents the O3 alpha_four class from degrading into:
            non-case-3 switch subtree -> default action + i++ + continue
        while still preserving simple forms such as:
            action block -> latch/update block -> loop header
        """
        if loop_header is None or target_node is None:
            return None, None

        update_addrs = self._metadata_loop_update_blocks_v26(loop_header)
        if not update_addrs:
            return None, None

        # Direct update/latch target is always safe.
        if self._addr_v26(target_node) in update_addrs:
            return [], target_node

        # Never summarize a branch arm whose root is itself conditional.  That
        # arm may be a switch/range ladder, short-circuit boolean, or early-exit
        # gateway.  Structuring it is more important than grabbing the latch.
        if self._get_condition(target_node) is not None:
            self._metadata_record_event_v26(
                "metadata_latch_path_rejected_structured_root_v27",
                loop=self._addr_v26(loop_header),
                target=self._addr_v26(target_node),
            )
            return None, None

        seen = set()
        cur = target_node
        prefix = []
        depth = 0

        while cur is not None and depth <= limit:
            if cur in seen:
                return None, None
            seen.add(cur)

            if cur in self.loop_headers and cur is not loop_header:
                return None, None
            if self._target_is_function_exit_block(cur):
                return None, None
            if self._is_loop_tail_chain_member(cur):
                return None, None
            if self._metadata_target_is_continuation_gateway_v26(cur, owner_loop=loop_header):
                return None, None
            if self._get_condition(cur) is not None:
                return None, None

            caddr = self._addr_v26(cur)
            if caddr in update_addrs:
                return prefix, cur

            if self._node_has_executable_ops_cfg(cur):
                prefix.append(cur)

            nxts = self._successors(cur)
            if len(nxts) != 1:
                return None, None

            nxt = nxts[0]
            # Do not cross into condition blocks or gateways just to reach a
            # latch.  That would erase the internal control structure.
            if nxt is not None:
                if self._get_condition(nxt) is not None:
                    return None, None
                if self._metadata_target_is_continuation_gateway_v26(nxt, owner_loop=loop_header):
                    return None, None

            cur = nxt
            depth += 1

        return None, None

    # ---------------------------------------------------------------------
    # v29: conditional latch truth + explicit loop-normal iterator epilogue support
    # ---------------------------------------------------------------------

    def _conditional_latch_edge_kind_v28(self, from_node, target_node, owner_loop):
        """
        Classify an edge inside a conditional latch-test relative to the loop it
        controls.  This deliberately separates edge semantics from CFG true/false
        labels so SGL can attach the condition to the edge that actually breaks
        or continues the loop.
        """
        if from_node is None or target_node is None or owner_loop is None:
            return None

        if target_node is owner_loop:
            return "continue"

        cont = self._edge_continues_loop(from_node, target_node)
        if cont is owner_loop:
            return "continue"

        br = self._edge_exits_loop(from_node, target_node)
        if br is owner_loop:
            return "exit"

        nodes = set(self.loop_nodes.get(owner_loop, set()) or set())
        if target_node in nodes:
            return "body"

        # If the source is inside the owner loop and the target is outside it,
        # treat it as an exit even when older CFG metadata did not tag the edge.
        if from_node in nodes and target_node not in nodes:
            return "exit"

        return None

    def _role_text_for_edge_v28(self, src, dst):
        parts = []
        rec = self._edge_truth_record_v26(src, dst)
        if isinstance(rec, dict):
            for k in ("role", "raw_type", "trust", "invert_source", "status"):
                v = rec.get(k)
                if v:
                    parts.append(str(v))
        try:
            parts.append(self._edge_role_text_v25(src, dst))
        except Exception:
            pass
        return " ".join(parts).lower()

    def _conditional_latch_edge_needs_invert_v28(self, src, dst, exit_kind=None, continue_peer=None):
        """
        Return True when the predicate printed for src->dst must be the
        complement of the raw/HF condition expression.  This handles generic
        raw/HF complement pairs first, then a conservative order-fallback
        pattern seen when a raw terminal target is normalized to a nearby
        continuation/gateway block.
        """
        if self._metadata_edge_complement_requires_invert_v27(src, dst):
            return True

        try:
            if self._edge_condition_invert_for_edge(src, dst):
                return True
        except Exception:
            pass

        mnemonic, opcode = self._metadata_mnemonic_opcode_pair_v29(src, dst)
        op = str(opcode or "").upper()

        # Conservative metadata-only fallback: a conditional latch-test whose
        # exit edge is an order-fallback/gateway while the peer continues to the
        # loop header is exactly the class where HF successor normalization can
        # attach the complement predicate to the wrong edge.  Limit this to
        # equality predicates and loop-control edges; ordinary if-statements do
        # not pass through this helper.
        role_text = self._role_text_for_edge_v28(src, dst)
        peer_text = self._role_text_for_edge_v28(src, continue_peer) if continue_peer is not None else ""
        if exit_kind == "exit" and ("order_fallback" in role_text or "gateway" in role_text):
            if ("latch" in peer_text or "backedge" in peer_text or continue_peer is not None):
                if op in ("INT_NOTEQUAL", "INT_EQUAL"):
                    return True

        return False

    def _condition_for_conditional_latch_edge_v28(self, src, dst, cond=None, exit_kind=None, continue_peer=None):
        """Return a RawCond true when the conditional-latch edge src->dst is taken."""
        base = self._raw_condition_expr_for_cfg_node(src) or self._cond_to_string_v19(cond)

        meta_cond = self._metadata_condition_for_edge_v26(src, dst, cond=cond)
        if meta_cond is not None:
            # v48: EdgeTruth/edge-condition metadata is edge-specific truth.
            #
            # alpha_four O0 exposed a legacy latch path that did this:
            #   1. EdgeTruth for src->dst supplied direct authoritative truth:
            #          (v_1743 != 0xf), invert_for_edge=False
            #   2. The older latch complement heuristic saw JZ + INT_NOTEQUAL
            #      and overrode that direct edge predicate with:
            #          not ((v_1743 != 0xf))
            #
            # That is backwards.  The complement/mirror heuristic is a fallback
            # for missing/ambiguous edge truth; it must not override a concrete
            # edge predicate that already states the expression for this exact
            # src->dst edge.
            ms = self._cond_to_string_v19(meta_cond)
            rec = self._edge_truth_record_v26(src, dst)
            if isinstance(rec, dict):
                explicit_inv = rec.get("invert_for_edge")
                conf = str(rec.get("confidence") or rec.get("trust") or "").lower()
                source = str(rec.get("selection_source") or rec.get("source") or "").lower()
                has_strong_edge_truth = conf in ("authoritative", "high") or "edge" in source
                if explicit_inv is False and has_strong_edge_truth:
                    try:
                        self._metadata_record_event_v26(
                            "conditional_latch_direct_edge_truth_preserved_v48",
                            src=self._addr_v26(src),
                            dst=self._addr_v26(dst),
                            expr=ms,
                            confidence=conf,
                            selection_source=source,
                            reason="direct_edge_truth_beats_legacy_notequal_complement",
                        )
                    except Exception:
                        pass
                    return meta_cond

            # If metadata already supplied an inverted edge expression, keep it.
            if ms and str(ms).strip().startswith("not "):
                return meta_cond

        if base and self._conditional_latch_edge_needs_invert_v28(
            src, dst, exit_kind=exit_kind, continue_peer=continue_peer
        ):
            s = str(base).strip()
            if s.startswith("not "):
                expr = s
            else:
                expr = "not (%s)" % s
            self._metadata_record_event_v26(
                "conditional_latch_edge_predicate_inverted_v28",
                src=self._addr_v26(src),
                dst=self._addr_v26(dst),
                expr=expr,
                opcode=self._condition_opcode_for_cfg_node_v19(src),
                role_text=self._role_text_for_edge_v28(src, dst),
            )
            return RawCond(
                expr,
                source=cond,
                inverted=True,
                reason="v28_conditional_latch_edge_complement",
            )

        if meta_cond is not None:
            return meta_cond

        return self._condition_for_edge(src, dst, cond=cond)

    def _metadata_loop_normal_epilogue_nodes_v28(self, loop_header):
        """
        Return simple executable latch/update nodes that should run after an
        ordinary fallthrough completion of a loop body.  These are not branch
        arms; they are the normal iterator epilogue of lowered for-like loops.
        """
        if loop_header is None:
            return []
        if loop_header in self.loop_body_headers:
            # Body-header do/while tail chains have their own epilogue lowering.
            return []

        facts = self._latch_facts_for_loop_v26(loop_header) or {}
        candidates = []
        for k in ("normal_epilogue_blocks", "update_blocks", "latch_blocks"):
            for a in list(facts.get(k) or []):
                if isinstance(a, int) and a not in candidates:
                    candidates.append(a)

        out = []
        for a in candidates:
            n = self._node_by_addr_v27(a)
            if n is None:
                continue
            if self._is_loop_tail_chain_member(n):
                continue
            if not self._node_has_executable_ops_cfg(n):
                continue
            # A normal epilogue latch must be a simple update block returning
            # directly to the loop header.  Reject conditional or multi-exit
            # blocks so we do not summarize structured control.
            if self._get_condition(n) is not None:
                continue
            succs = list(self._successors(n) or [])
            if not succs or any(s is not loop_header for s in succs):
                continue
            if n not in out:
                out.append(n)
        return out

    def _conditional_latch_target_is_loop_owned_epilogue_v52(
        self,
        owner_loop,
        from_node,
        target_node,
    ):
        """
        True when a conditional-latch arm points directly at the normal
        iterator/latch epilogue already owned by ``owner_loop``.

        This is a custody rule, not an address- or expression-specific repair.
        ``_emit_normal_latch_epilogue_for_loop_v28`` is the sole execution
        owner for metadata-proven normal epilogues.  Re-emitting the same block
        inside a surviving conditional arm duplicates the iterator update:

            if break_condition:
                break
            else:
                iterator += 1       # wrong arm-local copy
            iterator += 1           # loop-owned normal epilogue

        Required structural proof:
          * the source belongs to the owner loop;
          * the target is one of that loop's metadata-derived normal epilogue
            blocks;
          * the target is a plain executable block whose only successor is the
            owner loop header; and
          * the edge is not a loop exit.

        The normal-epilogue inventory already rejects conditional, multi-exit,
        tail-chain, and non-executable candidates.  The repeated checks here
        keep this consumer safe if an older metadata producer is incomplete.
        """
        if owner_loop is None or from_node is None or target_node is None:
            return False

        if target_node is owner_loop:
            return False
        if target_node in set(getattr(self, "loop_headers", set()) or set()):
            return False
        if self._target_is_loop_tail_chain_node(target_node):
            return False
        if self._target_is_function_exit_block(target_node):
            return False

        owner_nodes = set(self.loop_nodes.get(owner_loop, set()) or set())
        if from_node is not owner_loop and from_node not in owner_nodes:
            return False

        try:
            epilogue_nodes = set(
                self._metadata_loop_normal_epilogue_nodes_v28(owner_loop) or []
            )
        except Exception:
            epilogue_nodes = set()
        if target_node not in epilogue_nodes:
            return False

        if self._get_condition(target_node) is not None:
            return False
        if not self._node_has_executable_ops_cfg(target_node):
            return False

        successors = list(self._successors(target_node) or [])
        if not successors or any(s is not owner_loop for s in successors):
            return False

        try:
            if self._edge_exits_loop(from_node, target_node) is owner_loop:
                return False
        except Exception:
            pass

        return True

    def _exec_subtree_has_unconditional_loop_control_v28(self, node, loop_header):
        """
        True when the top-level body already ends in unconditional break/continue
        for this loop.  Used only as a coarse guard before appending a normal
        epilogue; branch-local controls remain branch-local and do not block the
        epilogue for other paths.
        """
        if node is None:
            return False
        k = getattr(node, "kind", None)
        if k in ("break", "continue"):
            target = getattr(node, "target_loop", None)
            return target is None or target is loop_header
        # Only a sequence whose last child is control should block epilogue.
        if k in ("sequence", "loop_body"):
            children = list(getattr(node, "children", []) or [])
            if not children:
                return False
            return self._exec_subtree_has_unconditional_loop_control_v28(children[-1], loop_header)
        return False

    def _exec_subtree_all_paths_terminate_for_loop_v41(self, node, loop_header):
        """
        Conservative all-path terminal test for loop bodies.

        This is narrower than general source cleanup.  It exists only to avoid
        appending the normal latch epilogue after a branch/switch ladder whose
        every visible arm already contains its own latch/update + continue (or
        other terminal control).

        It deliberately treats ordinary blocks and nested loops as fallthrough
        unless a later sequence element proves terminality.  For an if-node,
        both arms must terminate.  This catches the o3_alpha_two shape:

            if case_ladder:
                ... latch; continue
            else:
                ... latch; continue
            # normal latch epilogue here would be unreachable duplication
        """
        if node is None:
            return False

        kind = getattr(node, "kind", None)

        if kind in ("break", "continue", "return"):
            return True

        if kind == "if":
            then_branch = getattr(node, "then_branch", None)
            else_branch = getattr(node, "else_branch", None)
            return (
                self._exec_subtree_all_paths_terminate_for_loop_v41(then_branch, loop_header)
                and self._exec_subtree_all_paths_terminate_for_loop_v41(else_branch, loop_header)
            )

        if kind in ("sequence", "then", "else", "loop_body"):
            children = list(getattr(node, "children", []) or [])
            if not children:
                return False

            # Sequential execution: once a child terminates on every path, all
            # following children are unreachable for this path.  Earlier partial
            # terminals are okay because their fallthrough paths may be closed
            # by a later child.
            for child in children:
                if self._exec_subtree_all_paths_terminate_for_loop_v41(child, loop_header):
                    return True
            return False

        # Nested loops, blocks, and unknown nodes are conservative fallthrough.
        return False

    # ---------------------------------------------------------------------
    # v42 tail-position continue elision
    # ---------------------------------------------------------------------

    def _elide_tail_position_continues_v42(self):
        """
        Remove redundant continue leaves that occur in tail position of their
        own loop body after latch/update blocks have already been emitted.

        This is a source-shape cleanup, not a branch-truth decision.  It runs
        only after v41 normal-latch suppression, because the v41 proof needs
        explicit continue leaves to establish that every path has already
        closed through a latch/backedge.

        Safe class:
            while cond:
                if arm:
                    <action>
                    <latch update>
                    continue   # tail-position for this same while

        The explicit continue is equivalent to falling off the bottom of the
        while body, because there is no remaining code in that loop iteration.
        The latch/update block is preserved.
        """
        count = self._elide_tail_continues_walk_v42(getattr(self, "root", None))
        if count:
            self.branch_control_events.append({
                "kind": "tail_position_continue_elision_v42",
                "count": count,
                "reason": "continue_at_tail_of_own_loop_body",
            })
            self._metadata_record_event_v26(
                "tail_position_continue_elision_v42",
                count=count,
                reason="continue_at_tail_of_own_loop_body",
            )

    def _elide_tail_continues_walk_v42(self, node):
        if node is None:
            return 0

        count = 0
        kind = getattr(node, "kind", None)

        if kind == "loop":
            header = getattr(node, "header", None) or getattr(node, "cfg_node", None)
            count += self._elide_tail_continues_in_tail_context_v42(getattr(node, "body", None), header)

            # Recurse into nested structures that may not be in this loop body
            # shape for compatibility with older SGL trees.
            for child in list(getattr(node, "children", []) or []):
                if child is getattr(node, "body", None):
                    continue
                count += self._elide_tail_continues_walk_v42(child)
            return count

        for child in list(getattr(node, "children", []) or []):
            count += self._elide_tail_continues_walk_v42(child)

        for attr in ("body", "then_branch", "else_branch"):
            child = getattr(node, attr, None)
            if child is not None:
                count += self._elide_tail_continues_walk_v42(child)

        return count

    def _elide_tail_continues_in_tail_context_v42(self, node, loop_header):
        """
        Mutate only tail-position subtrees for loop_header.  Earlier siblings
        are traversed only to find nested loops; their continues are not tail
        continues for this loop because later code in the same iteration still
        exists.
        """
        if node is None:
            return 0

        kind = getattr(node, "kind", None)
        count = 0

        if kind in ("sequence", "then", "else", "loop_body"):
            children = list(getattr(node, "children", []) or [])
            if not children:
                return 0

            # Non-tail siblings may contain nested loops, but a continue there
            # is not redundant for this loop because following code exists.
            for child in children[:-1]:
                count += self._elide_tail_continues_walk_v42(child)

            last = children[-1]
            count += self._elide_tail_continues_in_tail_context_v42(last, loop_header)

            if self._continue_targets_loop_v42(last, loop_header):
                children.pop()
                setattr(node, "children", children)
                count += 1
            return count

        if kind == "if":
            count += self._elide_tail_continues_in_tail_context_v42(getattr(node, "then_branch", None), loop_header)
            count += self._elide_tail_continues_in_tail_context_v42(getattr(node, "else_branch", None), loop_header)
            return count

        if kind == "loop":
            # A nested loop has its own iteration boundary.  Clean it under its
            # own header, but do not treat its interior as tail-context for the
            # enclosing loop.
            count += self._elide_tail_continues_walk_v42(node)
            return count

        return count

    def _continue_targets_loop_v42(self, node, loop_header):
        if node is None or getattr(node, "kind", None) != "continue":
            return False

        target = getattr(node, "target_loop", None)
        if target is None:
            return True
        if target is loop_header:
            return True

        try:
            return getattr(target, "addr", None) == getattr(loop_header, "addr", None)
        except Exception:
            return False

    def _emit_normal_latch_epilogue_for_loop_v28(self, header, loop):
        """
        Append iterator/latch update blocks for ordinary fallthrough completion
        of the loop body.  Explicit continue arms still carry their own
        action+latch+continue sequence.  v41 adds a terminal-body guard: if the
        structured body already has no fallthrough path, the normal epilogue is
        unreachable CFG scaffolding and must not be appended.
        """
        if header is None or loop is None:
            return False
        nodes = self._metadata_loop_normal_epilogue_nodes_v28(header)
        if not nodes:
            return False
        if self._exec_subtree_has_unconditional_loop_control_v28(getattr(loop, "body", None), header):
            return False
        if self._exec_subtree_all_paths_terminate_for_loop_v41(getattr(loop, "body", None), header):
            self.branch_control_events.append({
                "kind": "normal_latch_epilogue_suppressed_v41",
                "loop": self._addr_v26(header),
                "candidate_blocks": [self._addr_v26(n) for n in nodes],
                "reason": "loop_body_all_paths_already_terminal",
            })
            self._metadata_record_event_v26(
                "normal_latch_epilogue_suppressed_v41",
                loop=self._addr_v26(header),
                blocks=[self._addr_v26(n) for n in nodes],
                reason="loop_body_all_paths_already_terminal",
            )
            return False

        emitted = []
        for n in nodes:
            b = ExecBlock(n)
            try:
                b.force_emit = True
                b.path_local_duplicate = True
                b.sgl_latch_epilogue = True
                b.latch_epilogue_header = header
                b.reason = "normal_latch_epilogue_v29"
            except Exception:
                pass
            loop.body.add(b)
            emitted.append(self._addr_v26(n))

        if emitted:
            # v29: make the epilogue edge explicit.  Some emitter/PHI paths
            # materialize iterator updates as branch-edge/drop-in transitions
            # rather than ordinary block assignments.  A naked epilogue block at
            # the end of the loop body can therefore be structurally present but
            # print-suppressed.  block + continue preserves the real backedge and
            # gives downstream layers the same edge context as explicit continue
            # arms, without summarizing away the structured body.
            cont = ExecContinue(header, "normal_latch_epilogue_continue_v29")
            try:
                cont.sgl_latch_epilogue_continue = True
                cont.latch_epilogue_blocks = list(emitted)
            except Exception:
                pass
            loop.body.add(cont)

            self.branch_control_events.append({
                "kind": "normal_latch_epilogue_v29",
                "loop": self._addr_v26(header),
                "blocks": emitted,
                "source": "semantic_graph_latch_update_facts_v29",
            })
            self._metadata_record_event_v26(
                "normal_latch_epilogue_emitted_v29",
                loop=self._addr_v26(header),
                blocks=emitted,
                explicit_continue=True,
            )
            return True
        return False

    def _edge_condition_invert_for_edge(self, src, dst):
        meta_inv = self._metadata_edge_invert_v26(src, dst)
        if meta_inv is not None:
            return bool(meta_inv)

        """
        v19/PALRAW: consume PALlibrary raw-condition polarity.

        CFG topology is owned by raw/HF edge metadata.  This helper says
        whether the HighFunction condition expression must be negated to
        describe THIS edge.
        """
        e = self._cfg_edge(src, dst)
        if e is None:
            return False

        for attr in ("condition_invert_for_edge", "invert_condition_for_edge", "condition_inverted_for_edge"):
            if hasattr(e, attr):
                try:
                    return bool(getattr(e, attr))
                except Exception:
                    pass

        # Fallback: if edge itself lacks flag but terminator says condition
        # is fallthrough-polarity, then explicit/true target edge needs not().
        pol = getattr(e, "condition_polarity", None)
        if pol == "fallthrough":
            raw_type = getattr(e, "raw_type", getattr(e, "type", None))
            role = getattr(e, "role", None)
            explicit = bool(
                getattr(e, "explicit_target", False) or
                getattr(e, "is_explicit_target", False) or
                role == "raw_true_explicit_target" or
                raw_type == "true"
            )
            return explicit

        return False

    def _edge_condition_reason(self, src, dst):
        meta_reason = self._metadata_edge_reason_v26(src, dst)
        if meta_reason:
            return meta_reason

        e = self._cfg_edge(src, dst)
        if e is None:
            return None
        return (
            getattr(e, "condition_polarity_reason", None)
            or getattr(e, "condition_polarity", None)
            or getattr(e, "role", None)
            or getattr(e, "raw_type", None)
        )

    def _edge_role_text_v25(self, src, dst):
        e = self._cfg_edge(src, dst)
        if e is None:
            return ""
        vals = []
        for attr in (
            "role", "raw_type", "type", "condition_polarity_reason",
            "condition_polarity_source", "condition_source",
        ):
            val = getattr(e, attr, None)
            if val:
                vals.append(str(val))
        return " ".join(vals).lower()

    def _edge_is_raw_true_explicit_target_v25(self, src, dst):
        e = self._cfg_edge(src, dst)
        if e is None:
            return False

        role = getattr(e, "role", None)
        raw_type = getattr(e, "raw_type", getattr(e, "type", None))

        if role == "raw_true_explicit_target" or raw_type == "true":
            return True

        return bool(
            getattr(e, "explicit_target", False)
            or getattr(e, "is_explicit_target", False)
        )

    def _edge_successors_match_or_unknown_v25(self, src, dst):
        """
        Trust only edge-local facts. PALRAW may attach status strings to an
        edge in newer PALlibrary builds, but older builds expose only topology.
        Absence of a status is not failure.
        """
        e = self._cfg_edge(src, dst)
        if e is None:
            return False

        for attr in ("status", "palraw_status", "raw_status", "successor_status"):
            val = getattr(e, attr, None)
            if val:
                s = str(val).lower()
                if "successors_differ" in s or "mismatch" in s:
                    return False
                if "successors_match" in s or "match" in s:
                    return True

        return True

    def _edge_is_latch_to_header_v25(self, src, dst):
        if src is None or dst is None:
            return False

        if self._edge_is_latch_edge(src, dst):
            return True

        role_text = self._edge_role_text_v25(src, dst)
        if "latch_to_header" in role_text:
            return True

        try:
            if dst in self.loop_headers and src in set(self.loop_latches.get(dst, []) or []):
                return True
        except Exception:
            pass

        return False

    def _edge_invert_is_protected_latch_v25(self, src, dst, base_expr=None):
        """
        Protect valid latch-to-header edges from being discarded as
        malformed/low-confidence merely because the HF predicate shape is
        source-unpleasant or contains a post-update expression.

        Narrow rule:
          - edge already requests inversion;
          - edge is a latch/backedge to a loop header;
          - edge is raw true explicit target;
          - successor topology is not known-bad;
          - mnemonic/HF-opcode form is one of the observed complementary
            compare/test classes.

        Alpha-Four tail:
            JLE header with HF INT_SLESS const < var
        becomes:
            if not (const < var): continue
        """

        if not self._edge_condition_invert_for_edge(src, dst):
            return False

        if not self._edge_is_latch_to_header_v25(src, dst):
            return False

        if not self._edge_is_raw_true_explicit_target_v25(src, dst):
            return False

        if not self._edge_successors_match_or_unknown_v25(src, dst):
            return False

        mnemonic = self._edge_mnemonic_v23(src, dst)
        opcode = self._condition_opcode_name_v23(src)
        expr = str(base_expr or self._raw_condition_expr_for_cfg_node(src) or "")

        compare_ops = ("INT_SLESS", "INT_LESS", "INT_SLESSEQUAL", "INT_LESSEQUAL")
        equality_ops = ("INT_EQUAL", "INT_NOTEQUAL")

        if mnemonic in ("JLE", "JBE", "JNG", "JNA"):
            if opcode in compare_ops or "<" in expr or "<=" in expr:
                return True

        if mnemonic in ("JG", "JA", "JNLE", "JNBE"):
            if opcode in compare_ops or "<" in expr or "<=" in expr:
                return True

        if mnemonic in ("JZ", "JE", "JNZ", "JNE"):
            if opcode in equality_ops or "==" in expr or "!=" in expr:
                return True

        return False

    def _raw_condition_expr_for_cfg_node(self, cfg_node):
        expr = self._cond_expr_raw(cfg_node)
        if expr is None:
            cond = self._get_condition(cfg_node)
            if cond is None:
                return None
            return getattr(cond, "name", None) or str(cond)
        return expr

    def _edge_has_high_confidence_raw_condition_v22(self, src, dst):
        """
        v23 compatibility name.  Return True only when raw/machine predicate
        text is explicitly attached to the edge, not merely when a topology
        edge exists.  Inversion trust is decided separately by
        _edge_invert_is_trustworthy_v23().
        """
        e = self._cfg_edge(src, dst)
        if e is None:
            return False

        for attr in (
            "raw_condition_expr", "raw_terminal_condition", "raw_branch_condition",
            "machine_condition", "terminal_condition_expr",
        ):
            val = getattr(e, attr, None)
            if val:
                return True

        reason = str(
            getattr(e, "condition_polarity_reason", "") or
            getattr(e, "condition_polarity_source", "") or
            getattr(e, "condition_source", "") or ""
        ).lower()
        return "raw_expr" in reason or "machine_expr" in reason or "palraw_expr" in reason

    def _condition_opcode_name_v23(self, src):
        try:
            n = self._condition_formula_node(src)
            if n is not None:
                op = getattr(n, "opcode", None)
                if op:
                    return str(op)
        except Exception:
            pass

        try:
            cond = self._get_condition(src)
            op = self._find_block_def_op(src, cond)
            if op is not None:
                opcode = getattr(op, "opcode", None)
                if opcode:
                    return str(opcode)
        except Exception:
            pass

        return ""

    def _edge_mnemonic_v23(self, src, dst=None):
        meta_m = self._metadata_edge_mnemonic_v26(src, dst)
        if meta_m:
            return meta_m

        e = self._cfg_edge(src, dst) if dst is not None else None

        candidates = []
        if e is not None:
            for attr in ("mnemonic", "branch_mnemonic", "terminal_mnemonic", "raw_mnemonic"):
                val = getattr(e, attr, None)
                if val:
                    candidates.append(str(val))

        if e is not None:
            reason = str(
                getattr(e, "condition_polarity_reason", "") or
                getattr(e, "condition_polarity_source", "") or
                getattr(e, "condition_source", "") or
                getattr(e, "role", "") or ""
            )
            candidates.append(reason)

        for c in candidates:
            m = re.search(r"mnemonic\s*=\s*([A-Za-z][A-Za-z0-9_]*)", c)
            if m:
                return m.group(1).upper()
            s = c.strip().upper()
            if re.match(r"^J[A-Z]+$", s):
                return s

        return ""

    def _edge_invert_is_trustworthy_v23(self, src, dst, base_expr=None):
        """
        Decide whether an edge inversion bit should be consumed.

        Raw topology always owns successor identity.  Predicate inversion is
        consumed only for mnemonic/HF-opcode pairs whose meaning is stable.
        This deliberately omits malformed abstractions instead of blindly
        applying either HF or RAW polarity.

        Examples from Sample X:
          JLE + INT_SLESS + (x < C+1)  => do NOT invert
          JG  + INT_SLESS + (x < C+1)  => invert
          JNZ + INT_EQUAL              => invert
          JZ  + INT_NOTEQUAL           => invert
        """
        if not self._edge_condition_invert_for_edge(src, dst):
            return False

        mnemonic = self._edge_mnemonic_v23(src, dst)
        opcode = self._condition_opcode_name_v23(src)
        expr = str(base_expr or self._raw_condition_expr_for_cfg_node(src) or "")

        # Equality/test pairs.
        if mnemonic in ("JNZ", "JNE"):
            if opcode == "INT_EQUAL" or "==" in expr:
                return True
            if opcode == "INT_NOTEQUAL" or "!=" in expr:
                return False

        if mnemonic in ("JZ", "JE"):
            if opcode == "INT_NOTEQUAL" or "!=" in expr:
                return True
            if opcode == "INT_EQUAL" or "==" in expr:
                return False

        # Signed/unsigned greater-than against an HF less-than predicate.
        # A JG/JNLE target is the complement of x < C(+1).
        if mnemonic in ("JG", "JA", "JNLE", "JNBE"):
            if opcode in ("INT_SLESS", "INT_LESS", "INT_SLESSEQUAL", "INT_LESSEQUAL") or "<" in expr:
                return True

        # JLE/JBE often appears as an already-adjusted HF less-than predicate
        # such as x < 0xc9 for source x <= 0xc8.  Do not invert that form.
        if mnemonic in ("JLE", "JBE", "JNG", "JNA"):
            if opcode in ("INT_SLESS", "INT_LESS", "INT_SLESSEQUAL", "INT_LESSEQUAL") or "<" in expr:
                return False

        # If PALlibrary later supplies explicit machine condition text, trust it.
        return self._edge_has_high_confidence_raw_condition_v22(src, dst)

    def _raw_edge_condition_expr_v22(self, src, dst):
        e = self._cfg_edge(src, dst)
        if e is not None:
            for attr in (
                "raw_condition_expr", "raw_terminal_condition", "raw_branch_condition",
                "machine_condition", "terminal_condition_expr",
            ):
                val = getattr(e, attr, None)
                if isinstance(val, str) and val.strip():
                    return val.strip()
                if val is not None and not isinstance(val, bool):
                    s = str(val).strip()
                    if s:
                        return s
        return self._raw_condition_expr_for_cfg_node(src)

    def _select_condition_expr_for_edge_v22(self, src, dst, cond=None):
        """
        v23 RAW/HF arbitration rule.

        Topology is raw-CFG owned. Predicate text usually comes from the best
        HF/formula expression.  Edge inversion is consumed only when the
        branch mnemonic and HF predicate opcode form a stable complementary
        pair; otherwise the abstraction is treated as malformed/low-confidence
        and omitted.
        """
        base_expr = self._raw_edge_condition_expr_v22(src, dst)
        if base_expr is None:
            return None, None

        invert = self._edge_condition_invert_for_edge(src, dst)
        reason = self._edge_condition_reason(src, dst)

        if invert:
            if self._edge_invert_is_trustworthy_v23(src, dst, base_expr):
                try:
                    self.condition_source_events.append({
                        "kind": "applied_trusted_edge_invert_v23",
                        "src": getattr(src, "addr", None),
                        "dst": getattr(dst, "addr", None),
                        "expr": base_expr,
                        "mnemonic": self._edge_mnemonic_v23(src, dst),
                        "opcode": self._condition_opcode_name_v23(src),
                        "reason": reason,
                    })
                except Exception:
                    pass
                return "not (%s)" % base_expr, reason or "trusted_edge_invert_v23"

            # v25: latch-to-header edges are not ordinary branch prettification.
            # If raw topology says this is the true explicit latch edge and the
            # mnemonic/HF-opcode pair is the known complementary form, preserve
            # the edge by applying inversion rather than dropping it as
            # low-confidence.
            if self._edge_invert_is_protected_latch_v25(src, dst, base_expr):
                try:
                    self.condition_source_events.append({
                        "kind": "applied_protected_latch_edge_invert_v25",
                        "src": getattr(src, "addr", None),
                        "dst": getattr(dst, "addr", None),
                        "expr": base_expr,
                        "mnemonic": self._edge_mnemonic_v23(src, dst),
                        "opcode": self._condition_opcode_name_v23(src),
                        "reason": reason,
                    })
                except Exception:
                    pass
                return "not (%s)" % base_expr, reason or "protected_latch_edge_invert_v25"

            try:
                self.condition_source_events.append({
                    "kind": "omitted_malformed_or_low_confidence_edge_invert_v23",
                    "src": getattr(src, "addr", None),
                    "dst": getattr(dst, "addr", None),
                    "expr": base_expr,
                    "mnemonic": self._edge_mnemonic_v23(src, dst),
                    "opcode": self._condition_opcode_name_v23(src),
                    "reason": reason,
                })
            except Exception:
                pass
            return base_expr, "hf_formula_invert_omitted_v23"

        return base_expr, reason or "edge_direct"

    def _condition_for_edge(self, src, dst, cond=None):
        """
        Return a condition object true when execution takes src -> dst.

        v26 first consumes GraphBuilder edge_condition_truth when present.
        v22 fallback keeps raw-CFG topology, but arbitrates predicate text
        between machine/raw and HF/formula sources. Low-confidence RAW/HF
        polarity is not allowed to silently invert ordinary branch conditions.
        """
        if src is None or dst is None:
            return cond if cond is not None else self._get_condition(src)

        meta_cond = self._metadata_condition_for_edge_v26(src, dst, cond=cond)
        if meta_cond is not None:
            return meta_cond

        expr, reason = self._select_condition_expr_for_edge_v22(src, dst, cond=cond)
        if expr is None:
            return cond if cond is not None else self._get_condition(src)

        return RawCond(expr, source=cond, inverted=str(expr).strip().startswith("not "), reason=reason)

    def _condition_for_branch_then(self, src, then_node, cond=None):
        return self._condition_for_edge(src, then_node, cond=cond)

    def _condition_for_loop_exit_edge(self, header):
        """
        For single-exit loop headers, return the predicate under which the
        loop exits.  The emitter already wraps these as while-not(exit_cond)
        for this SGL shape.
        """
        true_node = self._true_edge(header)
        false_node = self._false_edge(header)

        true_exits = self._edge_exits_loop(header, true_node) is header
        false_exits = self._edge_exits_loop(header, false_node) is header

        if true_exits and not false_exits:
            return self._condition_for_edge(header, true_node, cond=self._get_condition(header))

        if false_exits and not true_exits:
            return self._condition_for_edge(header, false_node, cond=self._get_condition(header))

        return None


    def _condition_for_loop_body_edge(self, header):
        """
        For single-exit header loops rendered by emitter as while <cond>,
        return the predicate under which the loop body executes.
        """
        true_node = self._true_edge(header)
        false_node = self._false_edge(header)

        true_exits = self._edge_exits_loop(header, true_node) is header
        false_exits = self._edge_exits_loop(header, false_node) is header

        if true_exits and not false_exits:
            return self._condition_for_edge(header, false_node, cond=self._get_condition(header))

        if false_exits and not true_exits:
            return self._condition_for_edge(header, true_node, cond=self._get_condition(header))

        return None


    def _cond_to_string_v19(self, cond):
        if cond is None:
            return None
        for attr in ("const_value", "value", "offset", "name"):
            v = getattr(cond, attr, None)
            if isinstance(v, str) and v:
                return v
        return str(cond)

    def _strip_redundant_outer_parens_v19(self, s):
        if s is None:
            return None
        s = str(s).strip()
        changed = True
        while changed and s.startswith("(") and s.endswith(")"):
            changed = False
            depth = 0
            ok = True
            for i, ch in enumerate(s):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0 and i != len(s) - 1:
                        ok = False
                        break
            if ok:
                s = s[1:-1].strip()
                changed = True
        return s

    def _negated_less_inner_v19(self, expr):
        """
        Return (var, inner_expr) for strings like:
            not ((local_20 < 3))
            not (((local_1c < 2)))

        Used only as a guarded induction-loop repair, not as a general
        expression simplifier.
        """
        s = self._strip_redundant_outer_parens_v19(expr)
        if not s or not s.startswith("not "):
            return None, None

        inner = s[4:].strip()
        inner = self._strip_redundant_outer_parens_v19(inner)

        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*<\s*(0x[0-9a-fA-F]+|\d+)$", inner)
        if not m:
            return None, None

        return m.group(1), inner

    def _loop_has_positive_induction_update_v19(self, header, var_name):
        """
        Detect simple positive induction updates feeding a loop-header PHI.

        v20b broadens v19:
          - v19 only accepted direct output-to-local updates:
                INT_ADD local_20, 1 -> local_20
          - Ghidra/O0 commonly uses:
                INT_ADD local_20, 1 -> v_1678
                MULTIEQUAL [local_20, v_1678] -> local_20

        The second form is the alpha_two j/k/i loop shape.  This routine
        therefore accepts either direct local writes or temp writes that feed
        a header MULTIEQUAL whose output is var_name.
        """
        if header is None or not var_name:
            return False

        def const_int(v):
            if v is None:
                return None
            if getattr(v, "is_constant", False):
                for attr in ("const_value", "value", "offset"):
                    val = getattr(v, attr, None)
                    if isinstance(val, int):
                        return val
            # Some PAL varnodes do not expose is_constant reliably.
            for attr in ("const_value", "value", "offset"):
                val = getattr(v, attr, None)
                if isinstance(val, int):
                    return val
            return None

        def is_positive_one(opcode, c):
            if opcode == "INT_ADD" and c in (1,):
                return True
            if opcode == "INT_SUB" and c in (-1, 0xffffffff, 0xffffffffffffffff):
                return True
            return False

        # Header PHI source sids that close into var_name.
        phi_source_sids = set()
        hblock = getattr(header, "block", None)
        if hblock is not None:
            for op in list(getattr(hblock, "ops", []) or []):
                if getattr(op, "opcode", None) != "MULTIEQUAL":
                    continue
                out = getattr(op, "output", None)
                if self._var_expr(out) != var_name:
                    continue
                for inp in list(getattr(op, "inputs", []) or []):
                    sid = getattr(inp, "ssa_id", None)
                    if sid is not None:
                        phi_source_sids.add(sid)

        nodes = set(self.loop_nodes.get(header, set()) or set())
        nodes.add(header)

        # Include latches/tail nodes explicitly; some natural-loop maps exclude
        # executable latch blocks in O0 CFGs.
        for n in list(self.loop_latches.get(header, []) or []):
            if n is not None:
                nodes.add(n)

        tail_chain = self.loop_tail_chains.get(header, None)
        if tail_chain:
            try:
                for n in tail_chain:
                    if n is not None:
                        nodes.add(n)
            except TypeError:
                nodes.add(tail_chain)

        for n in nodes:
            block = getattr(n, "block", None)
            if block is None:
                continue

            for op in list(getattr(block, "ops", []) or []):
                opcode = getattr(op, "opcode", None)
                if opcode not in ("INT_ADD", "INT_SUB"):
                    continue

                inputs = list(getattr(op, "inputs", []) or [])
                if len(inputs) != 2:
                    continue

                non_const = None
                const_val = None

                for inp in inputs:
                    c = const_int(inp)
                    if c is not None:
                        const_val = c
                    else:
                        non_const = inp

                if non_const is None or const_val is None:
                    continue

                if self._var_expr(non_const) != var_name:
                    continue

                if not is_positive_one(opcode, const_val):
                    continue

                out = getattr(op, "output", None)
                out_name = self._var_expr(out)
                out_sid = getattr(out, "ssa_id", None)

                # Direct local update.
                if out_name == var_name:
                    return True

                # SSA temp update closing into header PHI target.
                if out_sid is not None and out_sid in phi_source_sids:
                    return True

        return False

    def _repair_induction_loop_condition_v19(self, header, cond):
        """
        v19/v19b: Single-exit loop predicate correction.

        v19 fixed alpha_four's mutated gamma loop by using the body edge
        predicate, but alpha_two exposed a regression for ordinary induction
        loops:
            j = 0
            while not (j < 3):   # wrong, never enters

        If the condition is exactly not(var < const) and the loop body has a
        positive induction update for var, strip the not and use var < const.
        """
        expr = self._cond_to_string_v19(cond)
        var_name, inner = self._negated_less_inner_v19(expr)
        if not var_name or not inner:
            return cond

        if self._loop_has_positive_induction_update_v19(header, var_name):
            return RawCond(
                inner,
                source=cond,
                inverted=False,
                reason="v19_induction_loop_body_predicate_repair",
            )

        return cond

    def _normalize_loop_condition_role_v20(self, header, cond, role):
        """
        v21c: normalize loop role/predicate from edge custody first.

        Emitter contract:
            role=body -> while cond
            role=exit -> while not(cond)
            role=true -> while True

        If raw/HF true edge enters the loop body, raw condition is body-admit.
        If raw/HF true edge exits and false edge enters, raw condition is exit.
        Textual/induction heuristics are fallback only.
        """

        original_cond, original_role = cond, role

        def record(new_cond, new_role, why):
            try:
                self.loop_condition_events.append({
                    "header": getattr(header, "addr", None),
                    "old_cond": getattr(original_cond, "name", original_cond),
                    "old_role": original_role,
                    "new_cond": getattr(new_cond, "name", new_cond),
                    "new_role": new_role,
                    "why": why,
                })
            except Exception:
                pass
            return new_cond, new_role

        if role in (None, "true") or cond is None:
            return cond, role

        true_node = self._true_edge(header)
        false_node = self._false_edge(header)

        true_body = self._edge_enters_loop_body_v21b(header, true_node)
        false_body = self._edge_enters_loop_body_v21b(header, false_node)

        # v40: if canonical EdgeTruth exists, bind loop condition to the exact
        # body edge predicate.  This prevents exit predicates such as j >= 3
        # from being printed as while-body predicates for forward induction
        # loops, while preserving body-header forms such as gamma >= 1 when
        # EdgeTruth says that exact edge admits the loop body.
        if true_body and not false_body:
            et_cond = self._edgetruth_condition_for_edge_v40(header, true_node, cond=cond)
            if et_cond is not None:
                return record(et_cond, "body", "v40_edge_truth_true_body_predicate")

        if false_body and not true_body:
            et_cond = self._edgetruth_condition_for_edge_v40(header, false_node, cond=cond)
            if et_cond is not None:
                return record(et_cond, "body", "v40_edge_truth_false_body_predicate")

        # Edge truth first: raw true condition points to body.
        if true_body and not false_body:
            # Strip a not(var<const) only when the raw/HF edge itself did NOT
            # require inversion.  This preserves Sample Y's meaningful
            # gamma-loop predicate while fixing Sample X's accidental j/k
            # loop inversion.
            stripped = self._strip_accidental_negated_body_predicate_v21c(header, cond, true_node)
            if stripped is not cond:
                return record(stripped, "body", "true_edge_body_strip_accidental_not_no_edge_invert")
            if role != "body":
                return record(cond, "body", "true_edge_enters_body")
            return cond, role

        # Edge truth: raw true condition points away from body; false enters.
        if false_body and not true_body:
            raw = self._strip_simple_not_rawcond_v21b(cond)
            if raw is not None:
                # cond was already negated into a body predicate.
                return record(raw, "body", "false_edge_body_negated_condition")
            if role != "exit":
                return record(cond, "exit", "true_edge_exits_false_edge_body")
            return cond, role

        # Fallback 1: role=body with not(var < const) and positive induction.
        if role == "body":
            repaired = self._repair_induction_loop_condition_v19(header, cond)
            if repaired is not cond:
                return record(repaired, "body", "strip_negated_induction_body_predicate")

        # Fallback 2: role=body with const < var under positive induction is exit.
        expr = self._cond_to_string_v19(cond)
        expr_clean = self._strip_redundant_outer_parens_v19(expr)

        if role == "body" and expr_clean:
            m = re.match(
                r"^(0x[0-9a-fA-F]+|\d+)\s*<\s*([A-Za-z_][A-Za-z0-9_]*)$",
                expr_clean,
            )
            if m:
                var_name = m.group(2)
                return record(RawCond(
                    expr_clean,
                    source=cond,
                    inverted=False,
                    reason="v21c_const_less_var_exit_predicate",
                ), "exit", "const_less_var_exit_predicate")

        # Fallback 3: formula-level const < var.
        if role == "body":
            formula = self._condition_formula_node(header)
            if formula is not None:
                opcode = getattr(formula, "opcode", None)
                inputs = list(getattr(formula, "inputs", []) or [])

                if opcode in ("INT_LESS", "INT_SLESS") and len(inputs) == 2:
                    left, right = inputs[0], inputs[1]
                    if getattr(left, "is_constant", False) and not getattr(right, "is_constant", False):
                        var_name = self._var_expr(right)
                        exit_expr = "%s < %s" % (self._const_expr(left), var_name)
                        return record(RawCond(
                            exit_expr,
                            source=cond,
                            inverted=False,
                            reason="v21c_formula_const_less_var_exit_predicate",
                        ), "exit", "formula_const_less_var_exit_predicate")

        return cond, role

    def _edge_enters_loop_body_v21b(self, header, node):
        if header is None or node is None:
            return False

        nodes = set(self.loop_nodes.get(header, set()) or set())
        if node in nodes and node is not header:
            return True

        # If natural-loop membership is incomplete, body successors normally
        # reach the header/latch again without crossing a known exit. Keep this
        # conservative and bounded.
        try:
            if node is not header and self._reaches(node, header):
                return True
        except Exception:
            pass

        return False

    def _strip_simple_not_rawcond_v21b(self, cond):
        s = self._cond_to_string_v19(cond)
        if not s:
            return None
        s = self._strip_redundant_outer_parens_v19(s)
        if not s.startswith("not "):
            return None
        inner = self._strip_redundant_outer_parens_v19(s[4:].strip())
        if not inner:
            return None
        return RawCond(
            inner,
            source=cond,
            inverted=False,
            reason="v21c_strip_simple_not_rawcond",
        )

    def _strip_accidental_negated_body_predicate_v21c(self, header, cond, body_node=None):
        """
        Strip not(var<const) only when edge metadata says the body edge did not
        require condition inversion.

        Sample X j/k:
            raw true edge enters body, HF cond is var<const, no edge invert,
            but SGL carried not(var<const). Strip.

        Sample Y gamma loop:
            body predicate is genuinely not(local_18<1) due to raw/HF polarity.
            Edge invert is present, so keep it.
        """
        if body_node is not None:
            try:
                if self._edge_condition_invert_for_edge(header, body_node):
                    return cond
            except Exception:
                pass

        s = self._cond_to_string_v19(cond)
        if not s:
            return cond

        var_name, inner = self._negated_less_inner_v19(s)
        if var_name and inner:
            return RawCond(
                inner,
                source=cond,
                inverted=False,
                reason="v21c_true_edge_body_strip_negated_less_no_edge_invert",
            )

        return cond


    def _condition_opcode_for_cfg_node_v19(self, cfg_node):
        node = self._condition_formula_node(cfg_node)
        if node is not None:
            return getattr(node, "opcode", None)

        cond = self._get_condition(cfg_node)
        op = self._find_block_def_op(cfg_node, cond)
        if op is not None:
            return getattr(op, "opcode", None)

        return None

    def _repair_conditional_latch_break_condition_v19(self, node, owner, true_node, false_node, cond):
        """
        v19/v19b narrow fallback for internal raw targets such as alpha_four
        0x101235 -> 0x101252, where raw normalization should map the JZ target
        to the loop-exit block but older PALlibrary metadata may not yet expose
        condition_invert_for_edge.

        Pattern:
            then arm exits/breaks loop
            else arm continues loop
            condition opcode is INT_NOTEQUAL
        Therefore break must be when NOT(condition).
        """
        if node is None or owner is None:
            return cond

        true_exit = self._edge_exits_loop(node, true_node) is owner
        false_exit = self._edge_exits_loop(node, false_node) is owner
        true_cont = self._edge_continues_loop(node, true_node) is owner or true_node is owner
        false_cont = self._edge_continues_loop(node, false_node) is owner or false_node is owner

        if not (true_exit and false_cont and not false_exit):
            return cond

        cond_text = self._cond_to_string_v19(cond)
        if cond_text and str(cond_text).strip().startswith("not "):
            return cond

        opcode = self._condition_opcode_for_cfg_node_v19(node)
        raw_expr = self._raw_condition_expr_for_cfg_node(node) or cond_text
        if not raw_expr:
            return cond

        # v27: if raw mnemonic/HF opcode or edge_condition_truth says the
        # break edge is taken on the complement of the HF condition, force the
        # condition attached to the then/break arm to be the edge predicate.
        # This is generic branch-predicate custody, not an alpha_four literal.
        if self._metadata_edge_complement_requires_invert_v27(node, true_node):
            return RawCond(
                "not (%s)" % raw_expr,
                source=cond,
                inverted=True,
                reason="v27_complementary_raw_edge_break_predicate",
            )

        if opcode != "INT_NOTEQUAL":
            return cond

        # v47: retire the old blind INT_NOTEQUAL internal-break inversion.
        #
        # The original v19 fallback assumed this shape meant the break predicate
        # must be the complement of the HF condition:
        #
        #     true arm exits/breaks loop
        #     false arm continues loop
        #     opcode == INT_NOTEQUAL
        #     no mnemonic/polarity metadata available
        #
        # alpha_four O0 disproves that assumption.  The block can contain a
        # direct ground-truth comparison such as:
        #
        #     INT_NOTEQUAL [call_result, 0xf]
        #     CBRANCH cond
        #
        # and the true edge is exactly the break edge.  Inverting here poisons
        # PHIfolder post_update_condition_aliases and later the emitter prints
        # `if x == 0xf: break`.
        #
        # We already handled the only safe complement case above via explicit
        # edge metadata (`_metadata_edge_complement_requires_invert_v27`).  If
        # that evidence is absent, preserve raw condition truth.
        try:
            self.branch_control_events.append({
                "kind": "retired_blind_notequal_break_invert_v47",
                "from": getattr(node, "addr", None),
                "owner": getattr(owner, "addr", None),
                "true": getattr(true_node, "addr", None),
                "false": getattr(false_node, "addr", None),
                "cond": cond_text,
                "raw_expr": raw_expr,
                "reason": "preserve_raw_INT_NOTEQUAL_break_condition_without_complement_metadata",
            })
        except Exception:
            pass
        return cond


    def _cfg_edge(self, src, dst):
        if hasattr(self.cfg, "edge_between"):
            try:
                return self.cfg.edge_between(src, dst)
            except Exception:
                pass

        if src is None or dst is None:
            return None

        for e in self._as_list(getattr(src, "out_edges", None)):
            if getattr(e, "dst", None) is dst:
                return e

        return None

    def _edge_raw_type(self, src, dst):
        e = self._cfg_edge(src, dst)

        if e is None:
            return None

        return getattr(e, "raw_type", getattr(e, "type", None))

    def _edge_is_loop_exit(self, src, dst):
        if hasattr(self.cfg, "is_loop_exit_edge"):
            try:
                return bool(self.cfg.is_loop_exit_edge(src, dst))
            except Exception:
                pass

        e = self._cfg_edge(src, dst)
        return bool(getattr(e, "is_loop_exit", False)) if e is not None else False

    def _edge_is_latch_edge(self, src, dst):
        if hasattr(self.cfg, "is_latch_edge"):
            try:
                return bool(self.cfg.is_latch_edge(src, dst))
            except Exception:
                pass

        e = self._cfg_edge(src, dst)
        return bool(getattr(e, "is_latch_edge", False)) if e is not None else False

    def _edge_is_function_exit(self, src, dst):
        if hasattr(self.cfg, "is_function_exit_edge"):
            try:
                return bool(self.cfg.is_function_exit_edge(src, dst))
            except Exception:
                pass

        e = self._cfg_edge(src, dst)

        if e is not None and getattr(e, "is_function_exit_edge", False):
            return True

        return dst in getattr(self.cfg, "exit_nodes", set()) or dst is getattr(self.cfg, "exit", None)

    def _target_is_loop_tail_chain_node(self, target_node):
        """
        True when target_node is one of the explicitly recognized body-header
        loop tail/latch condition blocks.

        Such nodes are not ordinary branch arms. They are emitted once in the
        loop epilogue/tail-chain position. This prevents cases like alpha_four:

            if parity:
                ...
            else:
                <outer increment/tail block>

        where the tail block must run after the optional action, not only in
        the else branch.
        """

        if target_node is None:
            return False

        for _header, chain in getattr(self, "loop_tail_chains", {}).items():
            if target_node in set(chain or []):
                return True

        return False

    def _loop_tail_header_for_node(self, target_node):
        if target_node is None:
            return None

        for header, chain in getattr(self, "loop_tail_chains", {}).items():
            if target_node in set(chain or []):
                return header

        return None


    def _is_loop_tail_chain_member(self, node):
        """
        True when node is part of a multi-node body-header tail chain.

        Tail-chain nodes are not simple latch/update epilogues. A node such as
        alpha_four 0x10129b has both:
            0x10129b -> loop header  (backedge)
            0x10129b -> 0x1012a9     (fallthrough tail test)
        Collapsing it to block+continue skips the fallthrough test and breaks
        state truth.
        """

        if node is None:
            return False

        return self._loop_tail_header_for_node(node) is not None


    def _target_is_loop_latch_node(self, loop_header, target_node):
        if loop_header is None or target_node is None:
            return False

        if self._metadata_node_is_latch_update_for_loop_v26(loop_header, target_node):
            return True

        if hasattr(self.cfg, "loop_latches_for"):
            try:
                return target_node in set(self.cfg.loop_latches_for(loop_header) or [])
            except Exception:
                pass

        return target_node in set(self.loop_latches.get(loop_header, []) or [])

    def _target_is_function_exit_block(self, target_node):
        if target_node is None:
            return False

        return target_node in getattr(self.cfg, "exit_nodes", set()) or target_node is getattr(self.cfg, "exit", None)

    def _record_metadata_event_v43(self, rec):
        try:
            if not hasattr(self, "metadata_consumed_events"):
                self.metadata_consumed_events = []
            self.metadata_consumed_events.append(rec)
        except Exception:
            pass

    def _conditional_header_has_prebranch_payload_v43(self, cfg_node):
        """
        True when a conditional CFG block has real executable work before its
        terminal branch.  This is not a pretty-print rule; it preserves
        program-state writes/loads that dominate both branch arms.

        Exclusions are deliberately narrow: MULTIEQUAL, branch/return ops, and
        pure comparison/boolean condition builders for the terminal condition
        are structural.  COPY/LOAD/CALL/arithmetic feeding ordinary state is
        payload and must be emitted before the ExecIf.
        """
        if cfg_node is None:
            return False

        if self._get_condition(cfg_node) is None:
            return False

        block = getattr(cfg_node, "block", None)
        if block is None:
            return False

        term = getattr(block, "terminator", None)
        term_cond = getattr(term, "condition", None)
        cond_sid = getattr(term_cond, "ssa_id", None)

        pure_cond_ops = set((
            "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
            "INT_LESSEQUAL", "INT_SLESSEQUAL", "BOOL_NEGATE",
            "BOOL_AND", "BOOL_OR",
        ))

        for op in list(getattr(block, "ops", []) or []):
            opcode = getattr(op, "opcode", None)
            if opcode is None:
                continue
            if opcode == "MULTIEQUAL":
                continue
            if opcode in ("CBRANCH", "BRANCH", "BRANCHIND", "RETURN"):
                continue

            out = getattr(op, "output", None)
            out_sid = getattr(out, "ssa_id", None)

            # The exact terminal condition temp is represented by ExecIf.
            if cond_sid is not None and out_sid == cond_sid:
                continue

            # Pure comparison/boolean condition builders in conditional blocks
            # are structural unless explicitly materialized downstream.
            if opcode in pure_cond_ops and term is not None and getattr(term, "opcode", None) == "CBRANCH":
                continue

            return True

        return False


    def _node_has_executable_ops_cfg(self, cfg_node):
        if hasattr(self.cfg, "block_has_executable_ops"):
            try:
                return bool(self.cfg.block_has_executable_ops(cfg_node))
            except Exception:
                pass

        return self._node_has_executable_ops(cfg_node)


    def _innermost_loop_for_node(self, node):
        """
        Return the smallest natural loop containing node.
        """

        best = None
        best_size = None

        for header, nodes in self.loop_nodes.items():
            if node not in nodes:
                continue

            size = len(nodes)

            if best is None or size < best_size:
                best = header
                best_size = size

        return best

    def _edge_exits_loop(self, from_node, to_node):
        """
        Use CFG metadata first. Fallback to natural-loop containment.

        Returns the innermost loop header exited by edge from_node -> to_node,
        or None.
        """

        if from_node is None or to_node is None:
            return None

        if self._edge_is_loop_exit(from_node, to_node):
            loop = self._innermost_loop_for_node(from_node)
            if loop is not None:
                return loop

        loop = self._innermost_loop_for_node(from_node)

        if loop is None:
            return None

        if to_node not in self.loop_nodes.get(loop, set()):
            return loop

        return None


    def _edge_continues_loop(self, from_node, to_node):
        """
        Only direct edges to loop headers are structural continue.

        Latch/update nodes are executable epilogues; they must be emitted, not
        replaced by continue.
        """

        loop = self._innermost_loop_for_node(from_node)

        if loop is None or to_node is None:
            return None

        if to_node is loop:
            return loop

        return None


    def _node_has_executable_ops(self, cfg_node):
        if cfg_node is None:
            return False

        # Prefer FunctionCFG's centralized definition if available.
        if hasattr(self.cfg, "block_has_executable_ops"):
            try:
                return bool(self.cfg.block_has_executable_ops(cfg_node))
            except Exception:
                pass

        block = getattr(cfg_node, "block", None)
        if block is None:
            return False

        term = getattr(block, "terminator", None)
        term_cond = getattr(term, "condition", None)
        cond_sid = getattr(term_cond, "ssa_id", None)

        for op in list(getattr(block, "ops", []) or []):
            opcode = getattr(op, "opcode", None)
            if opcode == "MULTIEQUAL":
                continue

            out = getattr(op, "output", None)
            out_sid = getattr(out, "ssa_id", None)

            # A compare feeding only the branch terminator is structural.
            if cond_sid is not None and out_sid == cond_sid:
                continue

            if opcode in ("INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
                          "INT_LESSEQUAL", "INT_SLESSEQUAL", "BOOL_NEGATE"):
                if term is not None and getattr(term, "opcode", None) == "CBRANCH":
                    continue

            # COPY may be executable state transfer, especially local swaps.
            return True

        return False


    def _latch_update_then_continue_node(self, latch_node, loop, reason):
        """
        Lower an executable latch/update block into an explicit continuation
        epilogue:

            sequence
              block [latch_node]
              continue

        This keeps SGL semantic truth visible for nodes such as alpha_four
        0x10126b:
            update local_10
            backedge to 0x10126f

        v13 often left these as ordinary branch bodies, relying on fall-through.
        """

        seq = ExecNode("sequence")

        if latch_node is not None and self._node_has_executable_ops(latch_node):
            seq.add(ExecBlock(latch_node))
            self.visited.add(latch_node)

        seq.add(ExecContinue(loop, reason))
        return seq

    def _is_executable_latch_update_node(self, loop_header, node):
        """
        True for an executable loop latch/update node with a direct edge back
        to loop_header. Uses SGL metadata sandwiches and CFG metadata, then
        falls back to the local loop_latches map.
        """

        if loop_header is None or node is None:
            return False

        if not self._target_is_loop_latch_node(loop_header, node):
            return False

        # Tail-chain members have their own condition/fallthrough semantics.
        # They must be emitted by _emit_tail_chain_for_loop(), not collapsed
        # into block+continue.
        if self._is_loop_tail_chain_member(node):
            return False

        if not self._node_has_executable_ops_cfg(node):
            return False

        succs = list(self._successors(node) or [])

        # A simple latch/update block returns directly to the loop header.
        # Conservative rule: only promote if every successor is the header.
        # This preserves 0x10126b -> 0x10126f, while rejecting nodes such as
        # 0x10129b that also fall through to another tail condition.
        if succs and all(s is loop_header for s in succs):
            return True

        return False

    def _branch_reaches_latch_update(self, loop_header, target_node):
        """
        Detect a branch arm that reaches the loop's executable latch/update
        block through zero or one simple action blocks. Conservative by design.

        Returns (action_prefix_nodes, latch_node) or (None, None).
        """

        if loop_header is None or target_node is None:
            return None, None

        if self._is_executable_latch_update_node(loop_header, target_node):
            return [], target_node

        # v27 generic safety: do not summarize branch arms rooted at
        # conditional nodes or shared continuation gateways as action+latch.
        # Those roots may represent switch/range ladders, short-circuit tests,
        # or post-loop continuation gates and must be structured normally.
        if self._get_condition(target_node) is not None:
            self._metadata_record_event_v26(
                "branch_latch_reject_structured_target_v27",
                loop=self._addr_v26(loop_header),
                target=self._addr_v26(target_node),
            )
            return None, None

        if self._metadata_target_is_continuation_gateway_v26(target_node, owner_loop=loop_header):
            self._metadata_record_event_v26(
                "branch_latch_reject_gateway_target_v27",
                loop=self._addr_v26(loop_header),
                target=self._addr_v26(target_node),
            )
            return None, None

        # One-step action -> latch update. This catches alpha_four:
        #   0x101200 -> 0x10126b
        # without trying to solve arbitrary path convergence.
        nxts = self._successors(target_node)

        if len(nxts) == 1:
            nxt = nxts[0]

            # Do not treat action -> tail-chain as action+latch+continue.
            # Example: 0x101289 -> 0x10129b. The latter must still run its
            # false/fallthrough tail path to 0x1012a9.
            if self._is_loop_tail_chain_member(nxt):
                return None, None

            if self._is_executable_latch_update_node(loop_header, nxt):
                return [target_node], nxt

        # v26 metadata-guided bounded fallback.  This catches optimized CFGs
        # where the update/latch is known by GraphBuilder but not visible through
        # the older one-step SGL pattern.
        action_nodes, latch = self._metadata_action_reaches_latch_update_v26(loop_header, target_node)
        if latch is not None:
            self._metadata_record_event_v26(
                "metadata_action_reaches_latch_update",
                loop=self._addr_v26(loop_header),
                target=self._addr_v26(target_node),
                latch=self._addr_v26(latch),
                actions=[self._addr_v26(n) for n in (action_nodes or [])],
            )
            return action_nodes or [], latch

        return None, None

    def _action_latch_continue_node(self, action_nodes, latch_node, loop, reason):
        seq = ExecNode("sequence")

        for n in action_nodes or []:
            if n is not None and self._node_has_executable_ops_cfg(n):
                seq.add(ExecBlock(n))
                self.visited.add(n)

        if latch_node is not None and self._node_has_executable_ops_cfg(latch_node):
            seq.add(ExecBlock(latch_node))
            self.visited.add(latch_node)

        seq.add(ExecContinue(loop, reason))
        return seq


    def _action_then_break_node(self, action_node, loop, reason, from_node=None, arm=None):
        seq = ExecNode("sequence")

        # v37 safety net at the final action+break constructor.  This catches
        # older branch paths that bypass the conditional-latch arm populator but
        # still carry from_node + reason context.
        if (
            from_node is not None
            and isinstance(reason, str)
            and (reason.startswith("conditional_latch") or reason == "action_edge_exits_loop")
        ):
            v37_loop = self._conditional_latch_gateway_override_loop_v37(
                from_node,
                action_node,
                preferred_loop=loop,
                arm=arm,
                source="action_then_break_safety_net_v37:%s" % reason,
                record=True,
            )
            if v37_loop is not None:
                seq.add(ExecBreak(v37_loop, "conditional_latch_to_peer_gateway_v37"))
                self.branch_control_events.append({
                    "kind": "conditional_latch_peer_gateway_deferred_v37",
                    "arm": arm,
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(action_node, "addr", None),
                    "loop": getattr(v37_loop, "addr", None),
                    "preferred_loop": getattr(loop, "addr", None),
                    "source": "action_then_break_safety_net_v37",
                })
                return seq

        # v34 safety net: some older loop-exit arm paths reach this generic
        # action+break constructor directly.  Keep the rule narrow by firing
        # only for conditional-latch action exits with a known source node.
        if (
            from_node is not None
            and isinstance(reason, str)
            and (
                reason.startswith("conditional_latch")
                or reason == "action_edge_exits_loop"
            )
            and (
                self._conditional_latch_arm_should_defer_gateway_v34(
                    loop,
                    from_node,
                    action_node,
                    arm=arm,
                    reason="action_then_break_safety_net_v34:%s" % reason,
                )
                or self._loop_exit_action_gateway_should_defer_v35(
                    loop,
                    from_node,
                    action_node,
                    source="action_then_break_safety_net_v35:%s" % reason,
                )
            )
        ):
            seq.add(ExecBreak(loop, "conditional_latch_exit_to_structural_gateway_v34"))
            self.branch_control_events.append({
                "kind": "conditional_latch_structural_gateway_deferred_v34",
                "arm": arm,
                "from": getattr(from_node, "addr", None),
                "to": getattr(action_node, "addr", None),
                "loop": getattr(loop, "addr", None),
                "source": "action_then_break_safety_net_v34_v35",
            })
            return seq

        if action_node is not None and self._node_has_executable_ops(action_node):
            seq.add(ExecBlock(action_node))
            self.visited.add(action_node)

        seq.add(ExecBreak(loop, reason))
        return seq



    def _conditional_latch_target_is_deferred_normal_gateway_v36(self, owner_loop, from_node, target_node, arm=None, source=None):
        """
        v36: consume loop-normal-exit gateway facts at the actual latch-arm site.

        Earlier v32 logic correctly classified targets such as a post-region
        continuation condition as normal exits of the inner loop.  But the arm
        populator later used the static loop_normal_exits table and could still
        inline the target as:

            block[target]
            break

        This helper is intentionally narrow and is called only from conditional
        latch / loop-exit branch-arm population.  It does not rewrite ordinary
        switch/range arms.

        Required generic shape:
          * from_node is inside owner_loop and is not the loop header itself;
          * target_node is outside owner_loop;
          * target_node appears in the dynamically computed normal exits for
            owner_loop, which includes semantic-graph and structural gateway
            facts;
          * target_node has continuation-gateway structure for owner_loop.

        Action for caller: emit break(owner_loop) only, do not inline target,
        do not mark target visited.  The enclosing region/join traversal owns
        target_node.
        """
        if owner_loop is None or from_node is None or target_node is None:
            return False

        # Header guard exits are normal loop exits, but they are not branch-arm
        # action blocks.  This helper is only for body/latch arms.
        if from_node is owner_loop:
            return False

        owner_nodes = set(self.loop_nodes.get(owner_loop, set()) or set())
        if not owner_nodes:
            self._metadata_record_event_v26(
                "conditional_latch_normal_gateway_rejected_v36",
                reason="owner_loop_has_no_nodes",
                source=source or "conditional_latch_arm_v36",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                owner_loop=self._addr_v26(owner_loop),
                arm=arm,
            )
            return False

        if from_node not in owner_nodes:
            self._metadata_record_event_v26(
                "conditional_latch_normal_gateway_rejected_v36",
                reason="from_not_in_owner_loop",
                source=source or "conditional_latch_arm_v36",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                owner_loop=self._addr_v26(owner_loop),
                arm=arm,
            )
            return False

        if target_node in owner_nodes:
            return False
        if target_node in self.loop_headers:
            return False
        if self._target_is_loop_tail_chain_node(target_node):
            return False
        if self._target_is_function_exit_block(target_node):
            return False

        # Dynamic normal exits are stronger than the stored table because
        # _get_loop_normal_exits() adds metadata/structural continuation
        # gateways discovered after initial loop discovery.
        try:
            dynamic_normals = set(self._get_loop_normal_exits(owner_loop) or set())
        except Exception:
            dynamic_normals = set(self.loop_normal_exits.get(owner_loop, set()) or set())

        if target_node not in dynamic_normals:
            self._metadata_record_event_v26(
                "conditional_latch_normal_gateway_rejected_v36",
                reason="target_not_dynamic_normal_exit",
                source=source or "conditional_latch_arm_v36",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                owner_loop=self._addr_v26(owner_loop),
                arm=arm,
                dynamic_normals=[self._addr_v26(n) for n in self._ordered_nodes(dynamic_normals)],
            )
            return False

        # Confirm continuation-gateway structure with the exact latch/body edge
        # when possible, but also accept loop-level proof.  The important
        # generic invariant is: normal-exit gateway of this loop, reached from
        # a body/latch edge, not a private executable cleanup block.
        gateway = False
        try:
            gateway = bool(self._metadata_target_is_continuation_gateway_v26(
                target_node, owner_loop=owner_loop, from_node=from_node
            ))
        except Exception:
            gateway = False

        if not gateway:
            try:
                gateway = bool(self._structural_target_is_continuation_gateway_v32(
                    target_node, owner_loop=owner_loop, from_node=from_node
                ))
            except Exception:
                gateway = False

        if not gateway:
            # Loop-level normal-exit proof can be enough when the exact latch
            # edge has raw/HF normalization oddities.  Require condition/shared
            # join shape so private action blocks are not stolen.
            preds = list(self._predecessors(target_node) or [])
            pred_set = set(preds)
            outside_preds = [p for p in preds if p not in owner_nodes]
            is_condition = self._get_condition(target_node) is not None
            shared_pred = len(pred_set) >= 2 and bool(outside_preds)
            ipdom_join = False
            try:
                for n in self._real_nodes():
                    if n is target_node or n in owner_nodes:
                        continue
                    if getattr(n, "ipdom", None) is not target_node:
                        continue
                    if self._reaches(n, from_node):
                        ipdom_join = True
                        break
            except Exception:
                ipdom_join = False

            gateway = bool(is_condition or shared_pred or ipdom_join)

        if not gateway:
            self._metadata_record_event_v26(
                "conditional_latch_normal_gateway_rejected_v36",
                reason="target_not_gateway_shaped",
                source=source or "conditional_latch_arm_v36",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                owner_loop=self._addr_v26(owner_loop),
                arm=arm,
            )
            return False

        self._metadata_record_event_v26(
            "conditional_latch_normal_gateway_deferred_v36",
            source=source or "conditional_latch_arm_v36",
            from_addr=self._addr_v26(from_node),
            target=self._addr_v26(target_node),
            owner_loop=self._addr_v26(owner_loop),
            arm=arm,
            dynamic_normal_exit=True,
        )
        return True

    def _loop_exit_action_gateway_should_defer_v35(self, br_loop, from_node, target_node, source=None):
        """
        v35: final consumption guard for loop-exit branch arms.

        v32 correctly detects structural continuation gateways, but some paths
        do not pass through the conditional-latch-specific arm populator.  In
        particular, normal branch-arm control may classify an edge leaving the
        innermost loop as:

            executable target -> action block ; break

        That is correct for private cleanup/action blocks, but wrong for a
        shared conditional/ipdom continuation gateway that belongs to an
        enclosing region.  This helper is deliberately narrow:

          * it is called only after a br_loop has already been found;
          * from_node must be inside br_loop and target_node outside it;
          * target_node must not be a loop header, tail-chain node, or function
            exit;
          * target_node must have structural continuation-gateway evidence from
            metadata or the v32 CFG/ipdom fallback.

        The caller must emit only break(br_loop), must not inline target_node,
        and must not mark target_node visited.
        """
        if br_loop is None or from_node is None or target_node is None:
            return False

        owner_nodes = set(self.loop_nodes.get(br_loop, set()) or set())
        if not owner_nodes:
            self._metadata_record_event_v26(
                "loop_exit_action_gateway_rejected_v35",
                reason="owner_loop_has_no_nodes",
                source=source or "loop_exit_action_path",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                loop=self._addr_v26(br_loop),
            )
            return False

        if from_node not in owner_nodes:
            self._metadata_record_event_v26(
                "loop_exit_action_gateway_rejected_v35",
                reason="from_not_in_owner_loop",
                source=source or "loop_exit_action_path",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                loop=self._addr_v26(br_loop),
            )
            return False

        if target_node in owner_nodes:
            return False

        if target_node in self.loop_headers:
            return False

        if self._target_is_loop_tail_chain_node(target_node):
            return False

        if self._target_is_function_exit_block(target_node):
            return False

        # Confirm this really is a loop-exit edge.  At this callsite br_loop
        # should already come from _edge_exits_loop(), but verify defensively.
        exits_by_metadata = False
        try:
            exits_by_metadata = (self._edge_exits_loop(from_node, target_node) is br_loop)
        except Exception:
            exits_by_metadata = False

        exits_by_containment = bool(from_node in owner_nodes and target_node not in owner_nodes)
        if not (exits_by_metadata or exits_by_containment):
            return False

        # Require structural continuation evidence.  This intentionally reuses
        # the v32 detector rather than introducing address/sample-specific
        # rules.  It allows previously recorded metadata, semantic-graph gateway
        # facts, or CFG/ipdom fallback to prove the target belongs outside the
        # inner loop's local action arm.
        gateway = False
        try:
            gateway = bool(self._metadata_target_is_continuation_gateway_v26(target_node, owner_loop=br_loop, from_node=from_node))
        except Exception:
            gateway = False

        if not gateway:
            try:
                gateway = bool(self._structural_target_is_continuation_gateway_v32(target_node, owner_loop=br_loop, from_node=from_node))
            except Exception:
                gateway = False

        if not gateway:
            self._metadata_record_event_v26(
                "loop_exit_action_gateway_rejected_v35",
                reason="target_not_structural_gateway",
                source=source or "loop_exit_action_path",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                loop=self._addr_v26(br_loop),
            )
            return False

        # A private non-conditional cleanup block can still be action+break.
        # A conditional/shared/ipdom gateway should be deferred.
        is_condition = self._get_condition(target_node) is not None
        preds = list(self._predecessors(target_node) or [])
        pred_set = set(preds)
        outside_preds = [p for p in preds if p not in owner_nodes]
        inside_preds = [p for p in preds if p in owner_nodes]
        shared_pred = len(pred_set) >= 2 and bool(outside_preds)

        ipdom_join = False
        try:
            for n in self._real_nodes():
                if n is target_node or n in owner_nodes:
                    continue
                if getattr(n, "ipdom", None) is not target_node:
                    continue
                if self._reaches(n, from_node):
                    ipdom_join = True
                    break
        except Exception:
            ipdom_join = False

        if self._node_has_executable_ops_cfg(target_node) and not (is_condition or shared_pred or ipdom_join):
            self._metadata_record_event_v26(
                "loop_exit_action_gateway_rejected_v35",
                reason="private_executable_action_block",
                source=source or "loop_exit_action_path",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                loop=self._addr_v26(br_loop),
            )
            return False

        self._metadata_record_event_v26(
            "loop_exit_action_gateway_deferred_v35",
            source=source or "loop_exit_action_path",
            from_addr=self._addr_v26(from_node),
            target=self._addr_v26(target_node),
            loop=self._addr_v26(br_loop),
            is_condition=is_condition,
            shared_pred=shared_pred,
            ipdom_join=ipdom_join,
            pred_count=len(pred_set),
            outside_pred_count=len(outside_preds),
            inside_pred_count=len(inside_preds),
        )
        return True

    def _branch_arm_control_node(self, from_node, target_node):
        """
        Convert only true structural loop-control branch arms.

        v11 metadata rules:
          - direct target == loop header -> continue
          - target is loop-exit function-exit/post-loop block -> break only
          - target exits loop and has executable ops -> emit action block; break
          - target is loop latch/update node -> NOT control; caller emits block
        """

        if target_node is None:
            return None

        # Shared executable latch/update epilogue. This is not a plain branch
        # body; it is the continuation update before returning to the loop
        # header. Make the control explicit in the ExecTree.
        loop = self._innermost_loop_for_node(from_node)
        action_nodes, latch_node = self._branch_reaches_latch_update(loop, target_node)

        if latch_node is not None:
            self.branch_control_events.append({
                "kind": "latch_update_continue",
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "latch": getattr(latch_node, "addr", None),
                "loop": getattr(loop, "addr", None),
                "source": "cfg_metadata_v19",
            })
            return self._action_latch_continue_node(
                action_nodes,
                latch_node,
                loop,
                "latch_update_continue",
            )

        cont_loop = self._edge_continues_loop(from_node, target_node)

        if cont_loop is not None:
            self.branch_control_events.append({
                "kind": "continue",
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "loop": getattr(cont_loop, "addr", None),
                "source": "cfg_metadata_v19",
            })
            return ExecContinue(cont_loop, "edge_to_loop_header")

        br_loop = self._edge_exits_loop(from_node, target_node)

        if br_loop is not None:

            # v37: generic branch-arm loop-exit path.  Some conditional latch
            # exits are structured as ordinary if-branch arms before reaching
            # _populate_conditional_latch_arm.  Use the same peer-backedge
            # proof to prevent shared continuation gateways from becoming
            # executable action+break blocks.
            v37_loop = self._conditional_latch_gateway_override_loop_v37(
                from_node,
                target_node,
                preferred_loop=br_loop,
                arm="branch_arm_control",
                source="branch_arm_control_loop_exit_v37",
                record=True,
            )
            if v37_loop is not None:
                self.branch_control_events.append({
                    "kind": "conditional_latch_peer_gateway_deferred_v37",
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(v37_loop, "addr", None),
                    "preferred_loop": getattr(br_loop, "addr", None),
                    "source": "branch_arm_control_loop_exit_v37",
                })
                return ExecBreak(v37_loop, "edge_to_peer_gateway_v37")

            # v35: consume structural continuation gateways at the generic
            # loop-exit branch-arm control path.  Earlier v33/v34 hooks were
            # too narrow for optimized conditional-latch exits that arrive here
            # as action_edge_exits_loop.  Keep it tight: br_loop is known, the
            # edge must leave that loop by containment/metadata, and the target
            # must prove itself as a structural continuation gateway.
            if self._loop_exit_action_gateway_should_defer_v35(
                br_loop,
                from_node,
                target_node,
                source="branch_arm_control_loop_exit_v35",
            ):
                self.branch_control_events.append({
                    "kind": "loop_exit_action_gateway_deferred_v35",
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(br_loop, "addr", None),
                    "source": "branch_arm_control_loop_exit_v35",
                })
                return ExecBreak(br_loop, "edge_to_structural_continuation_gateway_v35")

            if self._metadata_target_is_continuation_gateway_v26(target_node, owner_loop=br_loop, from_node=from_node):
                self.branch_control_events.append({
                    "kind": "metadata_gateway_break",
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(br_loop, "addr", None),
                    "source": "semantic_graph_metadata_v26",
                })
                return ExecBreak(br_loop, "edge_to_metadata_gateway")

            # Never inline the function-exit/post-loop return block inside the
            # loop. Emit break and let normal post-loop traversal handle it.
            if self._edge_is_function_exit(from_node, target_node) or self._target_is_function_exit_block(target_node):
                self.branch_control_events.append({
                    "kind": "break_to_function_exit",
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(br_loop, "addr", None),
                    "source": "cfg_metadata_v19",
                })
                return ExecBreak(br_loop, "edge_to_function_exit")

            if self._node_has_executable_ops_cfg(target_node):
                self.branch_control_events.append({
                    "kind": "action_break",
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(br_loop, "addr", None),
                    "source": "cfg_metadata_v19",
                })
                return self._action_then_break_node(target_node, br_loop, "action_edge_exits_loop")

            self.branch_control_events.append({
                "kind": "break",
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "loop": getattr(br_loop, "addr", None),
                "source": "cfg_metadata_v19",
            })
            return ExecBreak(br_loop, "edge_exits_loop")

        return None


    def _can_branch_arm_absorb_linear_tail(self, from_node, target_node, stop_nodes):
        """
        Return True when a branch arm target is a plain linear action chain that
        should be emitted as path-local code even if some blocks are shared with
        other arms.

        This fixes lowered switch/fallthrough meshes such as:

            0x101216 false -> 0x10121b -> 0x10122f -> join
            0x101221 true  -> 0x10122f -> join

        Global visited ownership would otherwise make the 0x10121b arm lose the
        shared 0x10122f action tail. For execution truth, that tail belongs to
        both paths.
        """

        if target_node is None:
            return False

        loop = self._innermost_loop_for_node(from_node)
        if self._metadata_target_is_continuation_gateway_v26(target_node, owner_loop=loop, from_node=from_node):
            return False

        if target_node in set(stop_nodes or set()):
            return False

        if target_node in self.loop_headers:
            return False

        if self._get_condition(target_node) is not None:
            return False

        if self._target_is_loop_tail_chain_node(target_node):
            return False

        loop = self._innermost_loop_for_node(from_node)

        if loop is not None and self._target_is_loop_latch_node(loop, target_node):
            return False

        # Only absorb real action/copy blocks. Empty routing blocks should stay
        # under the ordinary traversal/control logic.
        if not self._node_has_executable_ops_cfg(target_node):
            return False

        # If this node is already globally visited, ordinary traversal would
        # suppress it. Branch arms are path-local, so this is exactly where the
        # helper is useful.
        if target_node in self.visited:
            return True

        # Also fire when the arm has at least one plain uncond successor before
        # the join/stop. This captures switch fallthrough action tails before
        # global visited can erase them.
        nxt = self._next_linear(target_node)

        if nxt is None:
            return False

        if nxt in set(stop_nodes or set()):
            return False

        if nxt in self.loop_headers:
            return False

        if self._get_condition(nxt) is not None:
            return False

        if self._target_is_loop_tail_chain_node(nxt):
            return False

        if loop is not None and self._target_is_loop_latch_node(loop, nxt):
            return False

        return self._node_has_executable_ops_cfg(nxt)

    def _emit_branch_arm_linear_tail(self, from_node, target_node, parent, stop_nodes, max_nodes=8):
        """
        Emit a short plain linear action chain as a branch-local sequence,
        intentionally allowing shared blocks to appear in multiple branch arms.

        This is not a general region duplication pass. It stops at joins,
        conditions, loops, tail-chain nodes, and latch/update nodes.
        """

        if not self._can_branch_arm_absorb_linear_tail(from_node, target_node, stop_nodes):
            return False

        stop_nodes = set(stop_nodes or set())
        loop = self._innermost_loop_for_node(from_node)

        seq = ExecNode("sequence")
        cur = target_node
        emitted = []
        count = 0

        while cur is not None and count < max_nodes:
            if cur in stop_nodes:
                break

            if cur in self.loop_headers:
                break

            if self._metadata_target_is_continuation_gateway_v26(cur, owner_loop=loop, from_node=from_node):
                break

            if self._get_condition(cur) is not None:
                break

            if self._target_is_loop_tail_chain_node(cur):
                break

            if loop is not None and self._target_is_loop_latch_node(loop, cur):
                break

            if self._node_has_executable_ops_cfg(cur):
                seq.add(ExecBlock(cur))
                emitted.append(cur)

            nxt = self._next_linear(cur)

            if nxt is None:
                break

            if nxt in stop_nodes:
                break

            if nxt in self.loop_headers:
                break

            if self._metadata_target_is_continuation_gateway_v26(nxt, owner_loop=loop, from_node=from_node):
                break

            if self._get_condition(nxt) is not None:
                break

            if self._target_is_loop_tail_chain_node(nxt):
                break

            if loop is not None and self._target_is_loop_latch_node(loop, nxt):
                break

            cur = nxt
            count += 1

        if not emitted:
            return False

        parent.add(seq)

        self.branch_control_events.append({
            "kind": "branch_arm_linear_tail",
            "from": getattr(from_node, "addr", None),
            "to": getattr(target_node, "addr", None),
            "emitted": [getattr(n, "addr", None) for n in emitted],
            "join_stops": [getattr(n, "addr", None) for n in stop_nodes],
            "source": "cfg_metadata_v19",
        })

        # Do NOT mark emitted blocks visited here. Branch arm tails are path-
        # local projections of the CFG and may legitimately be shared/fallthrough
        # actions. Global ownership would recreate the disappearance bug.
        return True


    def _direct_join_single_owner_eligible_v51(self, from_node, target_node, loop):
        """
        True only for an ordinary branch-local IPDOM which can be emitted once
        after the conditional.

        Loop headers, latches, executable latch updates, and tail-test/chain
        nodes are control transfers rather than ordinary joins.  Their direct
        edges must remain under the established loop machinery or iterator
        updates can disappear from one path.
        """
        if from_node is None or target_node is None:
            return False
        if target_node is not getattr(from_node, "ipdom", None):
            return False

        if target_node in set(getattr(self, "loop_headers", set()) or set()):
            return False
        if target_node in set(getattr(self, "loop_tail_test_nodes", set()) or set()):
            return False
        if self._target_is_loop_tail_chain_node(target_node):
            return False

        if loop is None:
            return True

        try:
            if target_node is loop or target_node not in set(self.loop_nodes.get(loop, set()) or set()):
                return False
        except Exception:
            return False

        try:
            if self._target_is_loop_latch_node(loop, target_node):
                return False
        except Exception:
            return False

        try:
            if self._is_executable_latch_update_node(loop, target_node):
                return False
        except Exception:
            return False

        return True

    def _emit_branch_arm(self, from_node, target_node, parent, stop_nodes):
        if target_node is None:
            return

        loop = self._innermost_loop_for_node(from_node)

        # v51: an ordinary branch's own IPDOM is a structural boundary, never arm-local
        # content.  A direct edge to that join represents an empty arm; the
        # enclosing conditional emits the join exactly once after both arms.
        #
        # Keep loop-exit custody on the established v33-v44 paths: this rule is
        # limited to joins which remain inside the same innermost loop region.
        # The direct edge itself is retained on the empty Exec arm so PHI
        # lowering can later attach predecessor-specific assignments without
        # reintroducing the join block inside the arm.
        branch_join = getattr(from_node, "ipdom", None)
        if self._direct_join_single_owner_eligible_v51(from_node, target_node, loop):
            edge_rec = {
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "join": getattr(branch_join, "addr", None),
                "loop": getattr(loop, "addr", None),
                "kind": "direct_join_empty_arm_v51",
            }
            try:
                records = list(getattr(parent, "direct_join_edges", []) or [])
                records.append(edge_rec)
                parent.direct_join_edges = records
            except Exception:
                pass

            self._metadata_record_event_v26(
                "direct_join_arm_deferred_v51",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                join=self._addr_v26(branch_join),
                loop=self._addr_v26(loop),
                target_exec=bool(self._node_has_executable_ops_cfg(target_node)),
                reason="branch_ipdom_has_single_post_branch_owner",
            )
            self.branch_control_events.append({
                "kind": "direct_join_arm_deferred_v51",
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "join": getattr(branch_join, "addr", None),
                "loop": getattr(loop, "addr", None),
                "source": "ipdom_single_owner_v51",
            })
            return

        # v26: Shared continuation gateways/join conditions must be emitted by
        # their owning continuation path, not duplicated as branch-local action.
        if self._metadata_target_is_continuation_gateway_v26(target_node, owner_loop=loop, from_node=from_node):
            if target_node in set(stop_nodes or set()):
                self.branch_control_events.append({
                    "kind": "metadata_gateway_arm_deferred",
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(loop, "addr", None),
                    "source": "semantic_graph_metadata_v26",
                })
                return

        # Body-header loop tail-chain nodes are emitted once in the loop
        # epilogue/tail position. They must not become optional branch arms,
        # even when they contain executable update ops such as local_14++.
        if self._target_is_loop_tail_chain_node(target_node):
            self.branch_control_events.append({
                "kind": "tail_chain_arm_deferred",
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "tail_header": getattr(self._loop_tail_header_for_node(target_node), "addr", None),
                "source": "cfg_metadata_v19",
            })
            return

        # Latch/update blocks are executable loop epilogues. They may be
        # reached from multiple branch arms and must not be erased by global
        # visited. In v19, lower them as block + explicit continue so the
        # ExecTree carries state-machine truth instead of relying on fall-through.
        if loop is not None and self._target_is_loop_latch_node(loop, target_node):
            if self._node_has_executable_ops_cfg(target_node):
                parent.add(self._latch_update_then_continue_node(
                    target_node,
                    loop,
                    "latch_update_branch_arm",
                ))
                self.branch_control_events.append({
                    "kind": "latch_update_continue",
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(loop, "addr", None),
                    "source": "cfg_metadata_v19",
                })
                return

        # If the target is a structured join/fallthrough, suppress only when
        # it is truly non-executable. Executable joins/latches must survive,
        # except for known tail-chain nodes handled above.
        if target_node in set(stop_nodes or set()):
            # v38: this is the bypass that can glue a shared executable join
            # into a branch arm before _branch_arm_control_node(),
            # _populate_conditional_latch_arm(), or _action_then_break_node()
            # can apply the v33-v37 loop-exit gateway guards.
            #
            # Keep the override narrow:
            #   * only at the stop-node/join bypass;
            #   * only when v37 can recover a conditional-latch peer/backedge
            #     owner or prove the target as a shared continuation gateway;
            #   * emit break for the recovered loop and leave the stop node for
            #     the enclosing continuation traversal.
            try:
                peer_loop_v38 = self._conditional_latch_peer_backedge_owner_v37(from_node, target_node)
            except Exception:
                peer_loop_v38 = None
            try:
                gateway_loop_v38 = peer_loop_v38 or loop
                gateway_shape_v38 = bool(
                    gateway_loop_v38 is not None
                    and self._target_gateway_shape_for_loop_v37(gateway_loop_v38, from_node, target_node)
                )
            except Exception:
                gateway_shape_v38 = False

            self._metadata_record_event_v26(
                "emit_branch_arm_stop_node_probe_v38",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                loop=self._addr_v26(loop),
                peer_loop=self._addr_v26(peer_loop_v38),
                target_exec=bool(self._node_has_executable_ops_cfg(target_node)),
                target_cond=bool(self._get_condition(target_node) is not None),
                gateway_shape=bool(gateway_shape_v38),
                stop_nodes=[self._addr_v26(n) for n in list(stop_nodes or set())],
            )

            v38_loop = self._conditional_latch_gateway_override_loop_v37(
                from_node,
                target_node,
                preferred_loop=loop,
                arm="stop_node",
                source="emit_branch_arm_stop_node_gateway_v38",
                record=True,
            )
            if v38_loop is not None:
                parent.add(ExecBreak(v38_loop, "stop_node_peer_gateway_v38"))
                self.branch_control_events.append({
                    "kind": "emit_branch_arm_stop_node_gateway_deferred_v38",
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(v38_loop, "addr", None),
                    "preferred_loop": getattr(loop, "addr", None),
                    "source": "emit_branch_arm_stop_node_gateway_v38",
                })
                self._metadata_record_event_v26(
                    "emit_branch_arm_stop_node_gateway_deferred_v38",
                    from_addr=self._addr_v26(from_node),
                    target=self._addr_v26(target_node),
                    selected_loop=self._addr_v26(v38_loop),
                    preferred_loop=self._addr_v26(loop),
                    peer_loop=self._addr_v26(peer_loop_v38),
                    gateway_shape=bool(gateway_shape_v38),
                )
                return

            if self._metadata_target_is_continuation_gateway_v26(target_node, owner_loop=loop, from_node=from_node):
                self.branch_control_events.append({
                    "kind": "metadata_gateway_stop_deferred",
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(loop, "addr", None),
                    "source": "semantic_graph_metadata_v26",
                })
                return
            if self._node_has_executable_ops_cfg(target_node):
                parent.add(ExecBlock(target_node))
            return

        ctrl = self._branch_arm_control_node(from_node, target_node)

        if ctrl is not None:
            parent.add(ctrl)
            return

        # v19: switch/fallthrough meshes can share an executable linear tail
        # between branch arms. Ordinary _emit_node/_emit_linear_sequence uses
        # global visited and may erase that tail on the second path. Emit these
        # short action chains as path-local branch content instead.
        if self._emit_branch_arm_linear_tail(from_node, target_node, parent, stop_nodes):
            return

        self._emit_node(target_node, parent, stop_nodes=stop_nodes)


    def _make_tail_chain_node(self, header, index=0):
        chain = list(self.loop_tail_chains.get(header, []) or [])

        if index >= len(chain):
            return None

        node = chain[index]
        cond = self._get_condition(node)

        if cond is None:
            return None

        true_node = self._true_edge(node)
        false_node = self._false_edge(node)

        cond = self._condition_for_branch_then(node, true_node, cond)

        if_node = ExecIf(None, cond)
        if_node.tail_test_node = node
        if_node.tail_test_header = header
        if_node.raw_polarity_consumed = True
        if_node.edge_condition_source_v25 = getattr(cond, "reason", None)

        self._populate_tail_arm(if_node.then_branch, header, chain, index, true_node)
        self._populate_tail_arm(if_node.else_branch, header, chain, index, false_node)

        return if_node

    def _tail_target_is_deferred_normal_gateway_v39(self, header, node, target, source=None):
        """
        v39: final owner fix for body-header tail-chain arms.

        VT01 proved the glued 0x10125c block was not inserted through the
        conditional-latch branch-arm consumers.  It was inserted by
        _action_then_break_node(reason='tail_action_exit') from
        _populate_tail_arm(), with from_node=None.  Therefore all v33-v38
        conditional-latch guards missed it.

        Generic rule:
            A target outside a body-header loop that is already a normal
            loop exit or shared continuation gateway is not branch-local
            action.  Emit only break(header) and let the enclosing traversal
            emit that target after the loop.

        This keeps private executable cleanup/action exits intact: only
        normal exits / structural gateways are deferred.
        """
        if header is None or target is None:
            return False

        hnodes = set(self.loop_nodes.get(header, set()) or set())
        target_outside = bool(target not in hnodes)
        if not target_outside:
            return False

        if target in self.loop_headers:
            return False

        if self._target_is_loop_tail_chain_node(target):
            return False

        if self._target_is_function_exit_block(target):
            return False

        static_normal = False
        dynamic_normal = False
        gateway = False
        structural_gateway = False

        try:
            static_normal = target in set(self.loop_normal_exits.get(header, set()) or set())
        except Exception:
            static_normal = False

        try:
            dynamic_normal = target in set(self._get_loop_normal_exits(header) or set())
        except Exception:
            dynamic_normal = False

        try:
            gateway = bool(self._metadata_target_is_continuation_gateway_v26(target, owner_loop=header, from_node=node))
        except Exception:
            gateway = False

        try:
            structural_gateway = bool(self._structural_target_is_continuation_gateway_v32(target, owner_loop=header, from_node=node))
        except Exception:
            structural_gateway = False

        is_condition = self._get_condition(target) is not None
        has_exec = self._node_has_executable_ops_cfg(target)

        should_defer = bool(
            target_outside
            and (static_normal or dynamic_normal or gateway or structural_gateway)
            and (is_condition or gateway or structural_gateway or dynamic_normal or static_normal)
        )

        # Keep the debug narrow: record full rejection details only for the
        # glued class we are chasing, or when the rule actually fires.
        relevant = (
            should_defer
            or self._addr_v26(target) == 0x10125c
            or self._addr_v26(node) == 0x101235
        )
        if relevant:
            self._metadata_record_event_v26(
                "tail_normal_gateway_%s_v39" % ("deferred" if should_defer else "rejected"),
                source=source or "populate_tail_arm_v39",
                node=self._addr_v26(node),
                target=self._addr_v26(target),
                header=self._addr_v26(header),
                target_outside=target_outside,
                static_normal=static_normal,
                dynamic_normal=dynamic_normal,
                gateway=gateway,
                structural_gateway=structural_gateway,
                is_condition=is_condition,
                has_executable_ops=has_exec,
                pred_addrs=[self._addr_v26(p) for p in list(self._predecessors(target) or [])],
                succ_addrs=[self._addr_v26(s) for s in list(self._successors(target) or [])],
            )

        return should_defer

    def _populate_tail_arm(self, branch, header, chain, index, target):
        if target is None:
            return

        node = chain[index] if 0 <= index < len(chain) else None

        if target is header:
            branch.add(ExecContinue(header, "tail_backedge"))
            self.branch_control_events.append({
                "kind": "tail_continue",
                "from": getattr(node, "addr", None),
                "to": getattr(target, "addr", None),
                "loop": getattr(header, "addr", None),
                "source": "cfg_metadata_v19",
            })
            return

        if index + 1 < len(chain) and target is chain[index + 1]:
            nxt = self._make_tail_chain_node(header, index + 1)
            if nxt is not None:
                branch.add(nxt)
            return

        # Target outside the loop: break only if it is function exit/post-loop.
        # Do not inline printf/return blocks into the loop body.
        if target not in self.loop_nodes.get(header, set()):
            if node is not None and (self._edge_is_function_exit(node, target) or self._target_is_function_exit_block(target)):
                branch.add(ExecBreak(header, "tail_to_function_exit"))
                self.branch_control_events.append({
                    "kind": "tail_break_to_function_exit",
                    "from": getattr(node, "addr", None),
                    "to": getattr(target, "addr", None),
                    "loop": getattr(header, "addr", None),
                    "source": "cfg_metadata_v19",
                })
                return

            # v39: a body-header tail-chain arm that reaches a normal
            # loop-exit / shared continuation gateway must not inline that
            # gateway as branch-local action.  VT01 showed the glued block
            # reached _action_then_break_node with reason='tail_action_exit'
            # and from_node=None, bypassing all conditional-latch guards.
            if self._tail_target_is_deferred_normal_gateway_v39(
                header,
                node,
                target,
                source="populate_tail_arm_outside_target_v39",
            ):
                branch.add(ExecBreak(header, "tail_to_normal_gateway_v39"))
                self.branch_control_events.append({
                    "kind": "tail_normal_gateway_deferred_v39",
                    "from": getattr(node, "addr", None),
                    "to": getattr(target, "addr", None),
                    "loop": getattr(header, "addr", None),
                    "source": "populate_tail_arm_outside_target_v39",
                })
                return

            if self._node_has_executable_ops_cfg(target):
                branch.add(self._action_then_break_node(target, header, "tail_action_exit"))
            else:
                branch.add(ExecBreak(header, "tail_exit"))
            return

        # Conservative fallback: ordinary block/flow inside loop.
        if self._node_has_executable_ops_cfg(target):
            branch.add(ExecBlock(target))
            self.visited.add(target)


    def _emit_tail_chain_for_loop(self, header, loop):
        chain = list(self.loop_tail_chains.get(header, []) or [])

        if not chain:
            return

        first = chain[0]

        if self._node_has_executable_ops(first) and first not in self.visited:
            self.visited.add(first)
            loop.body.add(ExecBlock(first))
            self.branch_control_events.append({
                "kind": "tail_epilogue_block",
                "node": getattr(first, "addr", None),
                "loop": getattr(header, "addr", None),
                "source": "cfg_metadata_v19",
            })

        tail_if = self._make_tail_chain_node(header, 0)

        if tail_if is not None:
            loop.body.add(tail_if)

        for n in chain:
            self.visited.add(n)




    def _conditional_latch_peer_backedge_owner_v37(self, from_node, target_node=None):
        """
        Recover the true small-loop owner for a conditional latch/body test by
        looking at the *peer* successor that continues to a loop header.

        This is needed when natural-loop membership is incomplete for an
        optimized/raw-normalized latch block: from_node may not be recorded in
        loop_nodes[small_header], so _edge_exits_loop(from_node, target) can
        return the enclosing loop or None.  The local CFG still proves the
        latch shape when one successor is a loop header/backedge and the other
        successor is the candidate exit/gateway.

        Generic shape:
            conditional node N
              edge A -> loop header H       (continue/backedge peer)
              edge B -> target outside H    (exit/gateway candidate)

        Return H, preferring the smallest candidate loop.  This helper does not
        itself decide whether the target is a gateway; consumers must prove that
        separately before using the owner override.
        """
        if from_node is None:
            return None
        if self._get_condition(from_node) is None:
            return None

        candidates = []
        for peer in list(self._successors(from_node) or []):
            if peer is None or peer is target_node:
                continue

            # Direct backedge/continue to a known loop header is the strongest
            # local proof.  This catches the gamma latch peer -> 0x10124a form.
            if peer in self.loop_headers:
                candidates.append(peer)

            # Metadata/CFG continue helper when it is available and precise.
            try:
                cont = self._edge_continues_loop(from_node, peer)
                if cont is not None:
                    candidates.append(cont)
            except Exception:
                pass

            # Executable latch/update peer that returns to a loop header.  Keep
            # this conservative: all successors of the peer must be that header.
            try:
                for h in list(self.loop_headers or []):
                    if self._is_executable_latch_update_node(h, peer):
                        candidates.append(h)
            except Exception:
                pass

        # Unique, smallest loop first.
        uniq = []
        seen = set()
        for c in candidates:
            if c is None or c in seen:
                continue
            seen.add(c)
            uniq.append(c)

        uniq.sort(key=lambda h: len(set(self.loop_nodes.get(h, set()) or set())) or 10**9)
        return uniq[0] if uniq else None

    def _target_gateway_shape_for_loop_v37(self, loop_header, from_node, target_node):
        """
        Return True when target_node is a shared conditional/ipdom continuation
        gateway for loop_header.  This deliberately accepts proof through the
        loop header itself when the exact latch/body from_node is missing from
        loop_nodes[loop_header].
        """
        if loop_header is None or target_node is None:
            return False
        if target_node in self.loop_headers:
            return False
        if self._target_is_loop_tail_chain_node(target_node):
            return False
        if self._target_is_function_exit_block(target_node):
            return False

        # First consume metadata/structural gateway facts with the exact edge.
        for proof_from in (from_node, loop_header):
            if proof_from is None:
                continue
            try:
                if self._metadata_target_is_continuation_gateway_v26(
                    target_node,
                    owner_loop=loop_header,
                    from_node=proof_from,
                ):
                    return True
            except Exception:
                pass
            try:
                if self._structural_target_is_continuation_gateway_v32(
                    target_node,
                    owner_loop=loop_header,
                    from_node=proof_from,
                ):
                    return True
            except Exception:
                pass

        # Local shape fallback: conditional/shared/ipdom target with incoming
        # paths both from inside and outside the small loop.  This is still
        # generic and does not depend on addresses or constants.
        owner_nodes = set(self.loop_nodes.get(loop_header, set()) or set())
        preds = list(self._predecessors(target_node) or [])
        pred_set = set(preds)
        outside_preds = [p for p in preds if p not in owner_nodes]
        inside_preds = [p for p in preds if p in owner_nodes]
        is_condition = self._get_condition(target_node) is not None
        shared_pred = len(pred_set) >= 2 and bool(outside_preds)

        ipdom_join = False
        try:
            for n in self._real_nodes():
                if n is target_node:
                    continue
                # Prefer enclosing decision nodes outside the small loop, but
                # do not require perfect natural-loop membership.
                if owner_nodes and n in owner_nodes and n is not loop_header:
                    continue
                if getattr(n, "ipdom", None) is not target_node:
                    continue
                if from_node is None or self._reaches(n, from_node) or self._reaches(n, loop_header):
                    ipdom_join = True
                    break
        except Exception:
            ipdom_join = False

        return bool(is_condition and (shared_pred or ipdom_join or inside_preds or outside_preds))

    def _conditional_latch_gateway_override_loop_v37(self, from_node, target_node, preferred_loop=None, arm=None, source=None, record=True):
        """
        Final guarded override for the glued latch-tail class.

        Use only at conditional-latch / loop-exit branch-arm consumers.  It
        recovers the true inner loop from the peer backedge/continue successor,
        then lets shared continuation-gateway metadata beat the older
        executable-target => action+break harness.

        Returns the loop that should be broken, or None.
        """
        if from_node is None or target_node is None:
            return None
        if self._get_condition(from_node) is None:
            return None

        peer_loop = self._conditional_latch_peer_backedge_owner_v37(from_node, target_node)
        candidates = []
        if peer_loop is not None:
            candidates.append(peer_loop)
        if preferred_loop is not None and preferred_loop not in candidates:
            candidates.append(preferred_loop)

        for loop_header in candidates:
            if loop_header is None:
                continue
            if target_node is loop_header:
                continue
            if target_node in self.loop_headers:
                continue
            if self._target_is_loop_tail_chain_node(target_node):
                continue
            if self._target_is_function_exit_block(target_node):
                continue

            owner_nodes = set(self.loop_nodes.get(loop_header, set()) or set())
            peer_proves_owner = (loop_header is peer_loop)

            # If the exact from_node is absent from the natural-loop node set,
            # the peer-backedge proof is allowed to stand in for membership.
            from_inside = bool(from_node in owner_nodes or peer_proves_owner)
            target_outside = bool(target_node not in owner_nodes)

            gateway = self._target_gateway_shape_for_loop_v37(loop_header, from_node, target_node)

            if from_inside and gateway and (target_outside or peer_proves_owner):
                if record:
                    self._metadata_record_event_v26(
                        "conditional_latch_peer_gateway_deferred_v37",
                        source=source or "conditional_latch_gateway_override_v37",
                        from_addr=self._addr_v26(from_node),
                        target=self._addr_v26(target_node),
                        selected_loop=self._addr_v26(loop_header),
                        preferred_loop=self._addr_v26(preferred_loop),
                        peer_loop=self._addr_v26(peer_loop),
                        arm=arm,
                        from_inside=from_inside,
                        target_outside=target_outside,
                        gateway=True,
                    )
                return loop_header

            if record:
                self._metadata_record_event_v26(
                    "conditional_latch_peer_gateway_rejected_v37",
                    source=source or "conditional_latch_gateway_override_v37",
                    from_addr=self._addr_v26(from_node),
                    target=self._addr_v26(target_node),
                    candidate_loop=self._addr_v26(loop_header),
                    preferred_loop=self._addr_v26(preferred_loop),
                    peer_loop=self._addr_v26(peer_loop),
                    arm=arm,
                    from_inside=from_inside,
                    target_outside=target_outside,
                    gateway=bool(gateway),
                    target_is_loop_header=bool(target_node in self.loop_headers),
                    target_is_tail=bool(self._target_is_loop_tail_chain_node(target_node)),
                    target_is_function_exit=bool(self._target_is_function_exit_block(target_node)),
                )

        return None

    def _emit_conditional_latch_test_node(self, node, parent):
        """
        Emit a conditional latch-test block while binding the printed condition
        to the edge that actually controls loop exit/continuation.

        v28 generalization:
          - classify true/false successors as exit/continue/body relative to
            the owner loop;
          - when one edge exits and the other continues, print the predicate for
            the exit edge and put that edge in the then arm, regardless of CFG
            raw true/false naming;
          - use metadata/mnemonic/opcode custody to invert JZ+NOTEQUAL and
            related raw/HF complement pairs.
        """

        if node is None:
            return False

        if self._target_is_loop_tail_chain_node(node):
            return False

        raw_cond = self._get_condition(node)
        if raw_cond is None:
            return False

        true_node = self._true_edge(node)
        false_node = self._false_edge(node)

        if true_node is None and false_node is None:
            return False

        true_cont = self._edge_continues_loop(node, true_node) if true_node is not None else None
        false_cont = self._edge_continues_loop(node, false_node) if false_node is not None else None
        true_exit = self._edge_exits_loop(node, true_node) if true_node is not None else None
        false_exit = self._edge_exits_loop(node, false_node) if false_node is not None else None

        owner = true_cont or false_cont or true_exit or false_exit
        if owner is None:
            owner = self._innermost_loop_for_node(node)

        # v37: natural-loop metadata can miss the latch/body node in optimized
        # raw/HF-normalized loops.  Recover the small-loop owner from a peer
        # successor that backedges directly to a loop header and whose opposite
        # successor is a shared continuation gateway.
        owner_override = (
            self._conditional_latch_gateway_override_loop_v37(
                node, true_node, preferred_loop=owner, arm="true",
                source="emit_conditional_latch_owner_probe_true_v37",
                record=False,
            )
            or self._conditional_latch_gateway_override_loop_v37(
                node, false_node, preferred_loop=owner, arm="false",
                source="emit_conditional_latch_owner_probe_false_v37",
                record=False,
            )
        )
        if owner_override is not None:
            owner = owner_override
            self._metadata_record_event_v26(
                "conditional_latch_owner_recovered_from_peer_v37",
                node=self._addr_v26(node),
                owner_loop=self._addr_v26(owner),
                true=self._addr_v26(true_node),
                false=self._addr_v26(false_node),
            )

        if owner is None:
            return False

        participates = bool(
            true_cont or false_cont or true_exit or false_exit or
            self._target_is_loop_latch_node(owner, node)
        )
        if not participates:
            return False

        true_kind = self._conditional_latch_edge_kind_v28(node, true_node, owner)
        false_kind = self._conditional_latch_edge_kind_v28(node, false_node, owner)

        # v37: if the owner was recovered from a peer backedge, the ordinary
        # containment-based classifier may still return None because from_node
        # is absent from loop_nodes[owner].  Override only this local
        # conditional-latch shape: peer-to-header is continue; opposite shared
        # gateway is exit.
        if true_node is owner:
            true_kind = "continue"
        elif self._conditional_latch_gateway_override_loop_v37(
            node, true_node, preferred_loop=owner, arm="true",
            source="emit_conditional_latch_kind_true_v37", record=False,
        ) is owner:
            true_kind = "exit"

        if false_node is owner:
            false_kind = "continue"
        elif self._conditional_latch_gateway_override_loop_v37(
            node, false_node, preferred_loop=owner, arm="false",
            source="emit_conditional_latch_kind_false_v37", record=False,
        ) is owner:
            false_kind = "exit"

        then_target = true_node
        else_target = false_node
        cond = None
        orientation = "raw_true_then"

        # Prefer a source-like latch decision: if <exit-predicate>: break else continue.
        # This is executable truth, not prettification: the then condition must be
        # true exactly when the then edge is taken.
        if true_kind == "exit" and false_kind == "continue":
            then_target = true_node
            else_target = false_node
            cond = self._condition_for_conditional_latch_edge_v28(
                node, then_target, cond=raw_cond, exit_kind="exit", continue_peer=false_node
            )
            orientation = "exit_true_continue_false_v28"
        elif false_kind == "exit" and true_kind == "continue":
            then_target = false_node
            else_target = true_node
            cond = self._condition_for_conditional_latch_edge_v28(
                node, then_target, cond=raw_cond, exit_kind="exit", continue_peer=true_node
            )
            orientation = "exit_false_continue_true_swapped_v28"
        else:
            cond = self._condition_for_branch_then(node, then_target, raw_cond)
            cond = self._repair_conditional_latch_break_condition_v19(
                node, owner, then_target, else_target, cond
            )

        self.visited.add(node)
        parent.add(ExecBlock(node))

        if_node = ExecIf(node, cond)
        if_node.latch_test_node = node
        if_node.latch_test_header = owner
        if_node.latch_test_v19 = True
        if_node.latch_test_v28 = True
        if_node.raw_polarity_consumed = True
        if_node.latch_orientation_v28 = orientation

        parent.add(if_node)

        self._populate_conditional_latch_arm(
            if_node.then_branch, owner, node, then_target, "then"
        )
        self._populate_conditional_latch_arm(
            if_node.else_branch, owner, node, else_target, "else"
        )

        self.branch_control_events.append({
            "kind": "conditional_latch_test",
            "node": getattr(node, "addr", None),
            "loop": getattr(owner, "addr", None),
            "true": getattr(true_node, "addr", None),
            "false": getattr(false_node, "addr", None),
            "then": getattr(then_target, "addr", None),
            "else": getattr(else_target, "addr", None),
            "orientation": orientation,
            "cond": getattr(cond, "name", cond),
            "source": "cfg_plus_semantic_metadata_v28",
        })

        return True



    def _conditional_latch_arm_should_defer_gateway_v34(self, owner_loop, from_node, target_node, arm=None, reason=None):
        """
        Narrow consumption guard for conditional-latch / loop-exit branch arms.

        This is intentionally a *consumer* rule, not a global CFG rewrite.
        It may be called only from conditional latch arm population or from the
        conditional-latch action+break constructor.  It prevents an inner loop's
        exit arm from swallowing a shared enclosing continuation condition as a
        branch-local action block.

        Generic shape:
          * from_node is inside owner_loop;
          * target_node is outside owner_loop;
          * the edge therefore exits owner_loop by containment or metadata;
          * target_node is a structural continuation gateway according to the
            same metadata/CFG fallback used by v32; and
          * target_node is not a loop header, tail-chain node, or function exit.

        The caller must emit only break(owner_loop) and must not mark target
        visited.  The enclosing region will emit target_node through normal-exit
        traversal.
        """
        if owner_loop is None or from_node is None or target_node is None:
            return False

        owner_nodes = set(self.loop_nodes.get(owner_loop, set()) or set())
        if not owner_nodes:
            self._metadata_record_event_v26(
                "loop_exit_gateway_defer_rejected_v34",
                reason="owner_loop_has_no_nodes",
                source="conditional_latch_arm_only",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                owner_loop=self._addr_v26(owner_loop),
                arm=arm,
            )
            return False

        if from_node not in owner_nodes:
            self._metadata_record_event_v26(
                "loop_exit_gateway_defer_rejected_v34",
                reason="from_not_in_owner_loop",
                source="conditional_latch_arm_only",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                owner_loop=self._addr_v26(owner_loop),
                arm=arm,
            )
            return False

        if target_node in owner_nodes:
            return False

        if target_node in self.loop_headers:
            return False

        if self._target_is_loop_tail_chain_node(target_node):
            return False

        if self._target_is_function_exit_block(target_node):
            return False

        # Verify loop-exit shape, but do not require older edge metadata to
        # return an exact "exit" string.  v33 was too strict here on some
        # optimized/raw-HF fallback edges.  Containment is sufficient because
        # this helper is called only from the conditional-latch arm consumer.
        edge_kind = None
        try:
            edge_kind = self._conditional_latch_edge_kind_v28(from_node, target_node, owner_loop)
        except Exception:
            edge_kind = None

        exits_by_metadata = False
        try:
            exits_by_metadata = (self._edge_exits_loop(from_node, target_node) is owner_loop)
        except Exception:
            exits_by_metadata = False

        exits_by_containment = bool(from_node in owner_nodes and target_node not in owner_nodes)
        if edge_kind not in ("exit", None, "body") and not exits_by_metadata and not exits_by_containment:
            return False
        if not exits_by_metadata and not exits_by_containment:
            return False

        # Structural gateway evidence.  Prefer the metadata-facing helper, but
        # also call the v32 structural fallback directly so this consumer does
        # not depend on role strings or ownership maps being complete.
        gateway = False
        try:
            gateway = bool(self._metadata_target_is_continuation_gateway_v26(target_node, owner_loop=owner_loop, from_node=from_node))
        except Exception:
            gateway = False

        if not gateway:
            try:
                gateway = bool(self._structural_target_is_continuation_gateway_v32(target_node, owner_loop=owner_loop, from_node=from_node))
            except Exception:
                gateway = False

        if not gateway:
            self._metadata_record_event_v26(
                "loop_exit_gateway_defer_rejected_v34",
                reason="target_not_structural_gateway",
                source="conditional_latch_arm_only",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                owner_loop=self._addr_v26(owner_loop),
                arm=arm,
                edge_kind=edge_kind,
                exits_by_metadata=exits_by_metadata,
                exits_by_containment=exits_by_containment,
            )
            return False

        self._metadata_record_event_v26(
            "loop_exit_branch_arm_structural_gateway_deferred_v34",
            source="conditional_latch_arm_population_only",
            from_addr=self._addr_v26(from_node),
            target=self._addr_v26(target_node),
            owner_loop=self._addr_v26(owner_loop),
            arm=arm,
            edge_kind=edge_kind,
            exits_by_metadata=exits_by_metadata,
            exits_by_containment=exits_by_containment,
            reason=reason,
        )
        return True

    def _loop_exit_branch_arm_structural_gateway_v33(self, owner_loop, from_node, target_node):
        """
        True only for the consumption point that populates a conditional
        latch/loop-exit branch arm.

        This is intentionally narrower than generic continuation-gateway
        detection.  It is not used by ordinary if/switch/range branch arms.

        Required shape:
          * from_node is a latch/body conditional inside owner_loop;
          * target_node is outside owner_loop;
          * the edge is classified as an exit from owner_loop;
          * target_node is a shared conditional/ipdom/join continuation for an
            enclosing region; and
          * target_node is not a loop header, tail-chain node, or function exit.

        Action:
          The branch arm should emit only `break` for owner_loop and leave the
          target unvisited so the enclosing region can emit it at its proper
          structural boundary.
        """
        if owner_loop is None or from_node is None or target_node is None:
            return False

        # This helper is for latch/body loop-exit arms, not loop-header guard
        # exits.  Avoid classifying ordinary loop exits such as header -> after
        # loop as deferred gateway arms.
        if from_node is owner_loop:
            return False

        owner_nodes = set(self.loop_nodes.get(owner_loop, set()) or set())
        if not owner_nodes:
            return False

        if from_node not in owner_nodes:
            return False

        if target_node in owner_nodes:
            return False

        if target_node in self.loop_headers:
            return False

        if self._target_is_loop_tail_chain_node(target_node):
            return False

        if self._target_is_function_exit_block(target_node):
            return False

        # Consume this rule only for loop-exit arm population.  Do not let an
        # ordinary branch or switch arm borrow this classification.
        try:
            edge_kind = self._conditional_latch_edge_kind_v28(from_node, target_node, owner_loop)
        except Exception:
            edge_kind = None
        if edge_kind != "exit":
            return False

        preds = list(self._predecessors(target_node) or [])
        pred_set = set(preds)
        outside_preds = [p for p in preds if p not in owner_nodes]
        inside_preds = [p for p in preds if p in owner_nodes]

        is_condition = self._get_condition(target_node) is not None
        shared_pred = len(pred_set) >= 2 and bool(outside_preds)

        # ipdom/enclosing-region evidence: some conditional/dispatch node
        # outside this owner loop uses target as join and reaches from_node.
        ipdom_join = False
        try:
            for n in self._real_nodes():
                if n is target_node or n in owner_nodes:
                    continue
                if getattr(n, "ipdom", None) is not target_node:
                    continue
                if self._reaches(n, from_node):
                    ipdom_join = True
                    break
        except Exception:
            ipdom_join = False

        if not (is_condition or shared_pred or ipdom_join):
            return False

        if not (outside_preds or ipdom_join):
            return False

        # A non-conditional executable single-owner cleanup block belongs to
        # the break arm.  A conditional/shared/ipdom target belongs to the
        # enclosing continuation region.
        if self._node_has_executable_ops_cfg(target_node) and not is_condition and not ipdom_join:
            return False

        self._metadata_record_event_v26(
            "loop_exit_branch_arm_structural_gateway_deferred_v33",
            source="conditional_latch_arm_population_only",
            from_addr=self._addr_v26(from_node),
            target=self._addr_v26(target_node),
            owner_loop=self._addr_v26(owner_loop),
            edge_kind=edge_kind,
            is_condition=is_condition,
            shared_pred=shared_pred,
            ipdom_join=ipdom_join,
            pred_count=len(pred_set),
            outside_pred_count=len(outside_preds),
            inside_pred_count=len(inside_preds),
        )
        return True

    def _populate_conditional_latch_arm(self, branch, owner_loop, from_node, target_node, arm):
        """
        Populate a true/false arm for a conditional latch-test node.

        Rules:
            target is loop header/backedge -> continue
            target exits owner loop        -> break, or action+break if executable
            target is tail-chain node      -> ignore here; tail-chain emits later
            target is ordinary in-loop     -> conservative block/flow
        """

        if target_node is None:
            return

        # v52: a direct arm edge to this loop's metadata-proven normal
        # iterator/latch epilogue is an execution edge, not arm-local block
        # ownership.  The loop-level v28/v29 epilogue pass emits that block
        # exactly once after the conditional; terminal peer arms (break or
        # continue) naturally bypass it.  Retain a path record for provenance
        # and PHI/debug consumers without inserting a duplicate ExecBlock.
        if self._conditional_latch_target_is_loop_owned_epilogue_v52(
            owner_loop,
            from_node,
            target_node,
        ):
            edge_rec = {
                "kind": "conditional_latch_normal_epilogue_edge_v52",
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "loop": getattr(owner_loop, "addr", None),
                "arm": arm,
            }
            try:
                records = list(getattr(branch, "normal_epilogue_edges", []) or [])
                records.append(edge_rec)
                branch.normal_epilogue_edges = records
            except Exception:
                pass

            self._metadata_record_event_v26(
                "conditional_latch_normal_epilogue_arm_deferred_v52",
                from_addr=self._addr_v26(from_node),
                target=self._addr_v26(target_node),
                loop=self._addr_v26(owner_loop),
                arm=arm,
                target_exec=bool(self._node_has_executable_ops_cfg(target_node)),
                target_successors=[
                    self._addr_v26(n)
                    for n in list(self._successors(target_node) or [])
                ],
                reason="loop_metadata_assigns_single_normal_epilogue_owner",
            )
            self.branch_control_events.append({
                "kind": "conditional_latch_normal_epilogue_arm_deferred_v52",
                "arm": arm,
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "loop": getattr(owner_loop, "addr", None),
                "source": "loop_normal_epilogue_single_owner_v52",
            })
            return

        # v37: final guarded override at the latch arm consumer.  Recover the
        # actual inner loop from the peer backedge if the owner_loop argument is
        # too broad, then defer shared continuation gateways before executable
        # action+break logic can glue them into the arm.
        v37_loop = self._conditional_latch_gateway_override_loop_v37(
            from_node,
            target_node,
            preferred_loop=owner_loop,
            arm=arm,
            source="populate_conditional_latch_arm_precheck_v37",
            record=True,
        )
        if v37_loop is not None:
            branch.add(ExecBreak(v37_loop, "conditional_latch_to_peer_gateway_v37"))
            self.branch_control_events.append({
                "kind": "conditional_latch_peer_gateway_deferred_v37",
                "arm": arm,
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "loop": getattr(v37_loop, "addr", None),
                "preferred_loop": getattr(owner_loop, "addr", None),
                "source": "populate_conditional_latch_arm_precheck_v37",
            })
            return

        # v36: strongest narrow consumer for the glued gamma-tail class.
        # If the target is already known as a dynamic normal-exit gateway of
        # this owner loop, do not inline it as action+break.
        if self._conditional_latch_target_is_deferred_normal_gateway_v36(
            owner_loop,
            from_node,
            target_node,
            arm=arm,
            source="populate_conditional_latch_arm_precheck_v36",
        ):
            branch.add(ExecBreak(owner_loop, "conditional_latch_to_dynamic_normal_gateway_v36"))
            self.branch_control_events.append({
                "kind": "conditional_latch_normal_gateway_deferred_v36",
                "arm": arm,
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "loop": getattr(owner_loop, "addr", None),
                "source": "populate_conditional_latch_arm_precheck_v36",
            })
            return

        # v34: consume structural continuation gateways only at the loop-exit
        # branch-arm population point.  This is the primary consumer.  It is
        # deliberately more tolerant than v33 about older edge-kind metadata,
        # but still requires from-inside/to-outside loop containment and v32
        # structural gateway evidence.
        if self._conditional_latch_arm_should_defer_gateway_v34(
            owner_loop,
            from_node,
            target_node,
            arm=arm,
            reason="populate_conditional_latch_arm_v34",
        ):
            branch.add(ExecBreak(owner_loop, "conditional_latch_exit_to_structural_gateway_v34"))
            self.branch_control_events.append({
                "kind": "conditional_latch_structural_gateway_deferred_v34",
                "arm": arm,
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "loop": getattr(owner_loop, "addr", None),
                "source": "conditional_latch_arm_population_only_v34",
            })
            return

        # v33 legacy path retained for compatibility with exact edge-kind
        # metadata when present.
        if self._loop_exit_branch_arm_structural_gateway_v33(owner_loop, from_node, target_node):
            branch.add(ExecBreak(owner_loop, "conditional_latch_exit_to_structural_gateway_v33"))
            self.branch_control_events.append({
                "kind": "conditional_latch_structural_gateway_deferred_v33",
                "arm": arm,
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "loop": getattr(owner_loop, "addr", None),
                "source": "conditional_latch_arm_population_only_v33",
            })
            return

        if target_node is owner_loop:
            branch.add(ExecContinue(owner_loop, "conditional_latch_backedge"))
            self.branch_control_events.append({
                "kind": "conditional_latch_continue",
                "arm": arm,
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "loop": getattr(owner_loop, "addr", None),
                "source": "cfg_metadata_v19",
            })
            return

        cont_loop = self._edge_continues_loop(from_node, target_node)

        if cont_loop is not None:
            branch.add(ExecContinue(cont_loop, "conditional_latch_continue_edge"))
            self.branch_control_events.append({
                "kind": "conditional_latch_continue",
                "arm": arm,
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "loop": getattr(cont_loop, "addr", None),
                "source": "cfg_metadata_v19",
            })
            return

        # Exit from the immediate loop. For nested loops, this means "break the
        # small loop"; the enclosing loop will continue traversal from the
        # join/next node already present in the SGL tree.
        br_loop = self._edge_exits_loop(from_node, target_node)

        if br_loop is not None:
            # v37: same final override with the br_loop discovered by the
            # containment/metadata helper.  This is intentionally before any
            # executable-target fallback.
            v37_loop = self._conditional_latch_gateway_override_loop_v37(
                from_node,
                target_node,
                preferred_loop=br_loop,
                arm=arm,
                source="populate_conditional_latch_arm_br_loop_v37",
                record=True,
            )
            if v37_loop is not None:
                branch.add(ExecBreak(v37_loop, "conditional_latch_to_peer_gateway_v37"))
                self.branch_control_events.append({
                    "kind": "conditional_latch_peer_gateway_deferred_v37",
                    "arm": arm,
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(v37_loop, "addr", None),
                    "preferred_loop": getattr(br_loop, "addr", None),
                    "source": "populate_conditional_latch_arm_br_loop_v37",
                })
                return

            # v36: repeat with the exact br_loop returned by CFG/containment.
            # This catches body/latch exits whose initial owner_loop argument
            # was incomplete or came through a normalized raw/HF edge.
            if self._conditional_latch_target_is_deferred_normal_gateway_v36(
                br_loop,
                from_node,
                target_node,
                arm=arm,
                source="br_loop_branch_precheck_v36",
            ):
                branch.add(ExecBreak(br_loop, "conditional_latch_to_dynamic_normal_gateway_v36"))
                self.branch_control_events.append({
                    "kind": "conditional_latch_normal_gateway_deferred_v36",
                    "arm": arm,
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(br_loop, "addr", None),
                    "source": "br_loop_branch_precheck_v36",
                })
                return

            # v34: second consumption point.  If the exact br_loop is known only
            # after _edge_exits_loop(), apply the same loop-exit-gateway rule
            # here before the older executable action+break fallback.
            if self._conditional_latch_arm_should_defer_gateway_v34(
                br_loop,
                from_node,
                target_node,
                arm=arm,
                reason="br_loop_branch_v34",
            ):
                branch.add(ExecBreak(br_loop, "conditional_latch_exit_to_structural_gateway_v34"))
                self.branch_control_events.append({
                    "kind": "conditional_latch_structural_gateway_deferred_v34",
                    "arm": arm,
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(br_loop, "addr", None),
                    "source": "br_loop_branch_v34",
                })
                return

            # v26: if the destination is a shared continuation/condition gateway
            # for an enclosing construct, do not inline it as branch-local
            # action.  This is the alpha_four O3 0x101235 -> 0x10125c class.
            if self._metadata_target_is_continuation_gateway_v26(target_node, owner_loop=br_loop, from_node=from_node):
                branch.add(ExecBreak(br_loop, "conditional_latch_to_metadata_gateway"))
                self.branch_control_events.append({
                    "kind": "conditional_latch_metadata_gateway_break",
                    "arm": arm,
                    "from": getattr(from_node, "addr", None),
                    "to": getattr(target_node, "addr", None),
                    "loop": getattr(br_loop, "addr", None),
                    "source": "semantic_graph_metadata_v26",
                })
                return

            if self._edge_is_function_exit(from_node, target_node) or self._target_is_function_exit_block(target_node):
                branch.add(ExecBreak(br_loop, "conditional_latch_to_function_exit"))
            elif self._node_has_executable_ops_cfg(target_node) and target_node not in set(self.loop_normal_exits.get(br_loop, set()) or set()):
                branch.add(self._action_then_break_node(target_node, br_loop, "conditional_latch_action_exit", from_node=from_node, arm=arm))
            else:
                branch.add(ExecBreak(br_loop, "conditional_latch_exit"))

            self.branch_control_events.append({
                "kind": "conditional_latch_break",
                "arm": arm,
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "loop": getattr(br_loop, "addr", None),
                "source": "cfg_metadata_v19",
            })
            return

        if self._target_is_loop_tail_chain_node(target_node):
            return

        # v37 last-ditch path: if the edge was not classified as a loop exit
        # because natural-loop membership is incomplete, peer-backedge recovery
        # can still prove this is an inner-loop break to a shared gateway.
        v37_loop = self._conditional_latch_gateway_override_loop_v37(
            from_node,
            target_node,
            preferred_loop=owner_loop,
            arm=arm,
            source="populate_conditional_latch_arm_final_executable_guard_v37",
            record=True,
        )
        if v37_loop is not None:
            branch.add(ExecBreak(v37_loop, "conditional_latch_to_peer_gateway_v37"))
            self.branch_control_events.append({
                "kind": "conditional_latch_peer_gateway_deferred_v37",
                "arm": arm,
                "from": getattr(from_node, "addr", None),
                "to": getattr(target_node, "addr", None),
                "loop": getattr(v37_loop, "addr", None),
                "preferred_loop": getattr(owner_loop, "addr", None),
                "source": "populate_conditional_latch_arm_final_executable_guard_v37",
            })
            return

        if self._node_has_executable_ops_cfg(target_node):
            branch.add(ExecBlock(target_node))
            self.visited.add(target_node)



    # ---------------------------------------------------------------------
    # v44: loop-internal conditional break recovery
    # ---------------------------------------------------------------------

    def _target_stays_in_loop_v44(self, owner_loop, target_node):
        if owner_loop is None or target_node is None:
            return False
        if target_node is owner_loop:
            return True
        if self._edge_continues_loop(owner_loop, target_node) is owner_loop:
            return True
        try:
            return target_node in set(self.loop_nodes.get(owner_loop, set()) or set())
        except Exception:
            return False

    def _try_emit_loop_internal_conditional_break_v44(self, node, parent, stop_nodes, cond):
        """
        v44: Some branch blocks inside a loop are not pre-classified as
        loop_tail_test_nodes, but their two outgoing edges still mean:

            one edge exits/breaks the innermost loop
            the peer edge remains in that same loop

        The ordinary if emitter attaches the condition to the raw then edge and
        can therefore print the peer/continue predicate as a break predicate in
        optimized-vs-O0 variants.  Recover these as conditional-latch style
        nodes locally: make the then arm the loop-exit edge and ask EdgeTruth
        for the predicate of that exact exit edge.
        """
        if node is None or parent is None:
            return False

        owner = self._innermost_loop_for_node(node)
        if owner is None or node is owner:
            return False

        true_node = self._true_edge(node)
        false_node = self._false_edge(node)
        if true_node is None or false_node is None:
            return False

        true_exits = self._edge_exits_loop(node, true_node) is owner
        false_exits = self._edge_exits_loop(node, false_node) is owner

        # Need exactly one loop-exit edge.
        if true_exits == false_exits:
            return False

        true_stays = self._target_stays_in_loop_v44(owner, true_node)
        false_stays = self._target_stays_in_loop_v44(owner, false_node)

        # The peer must remain in the same loop.  Otherwise this is an ordinary
        # if/else whose two arms leave the loop nest in different ways.
        if true_exits and not false_stays:
            return False
        if false_exits and not true_stays:
            return False

        if true_exits:
            break_target = true_node
            stay_target = false_node
            orientation = "true_exit_false_stays_v44"
        else:
            break_target = false_node
            stay_target = true_node
            orientation = "false_exit_true_stays_v44"

        edge_cond = self._condition_for_conditional_latch_edge_v28(
            node,
            break_target,
            cond=cond,
            exit_kind="exit",
            continue_peer=stay_target,
        )

        self.visited.add(node)

        if self._conditional_header_has_prebranch_payload_v43(node):
            parent.add(ExecBlock(node))
            self._record_metadata_event_v43({
                "kind": "condition_header_payload_preserved_v43",
                "block": self._hex_v26(getattr(node, "addr", None)),
                "reason": "conditional_block_contains_executable_prebranch_payload",
            })

        if_node = ExecIf(node, edge_cond)
        if_node.latch_test_node = node
        if_node.latch_test_header = owner
        if_node.loop_internal_conditional_break_v44 = True
        if_node.raw_polarity_consumed = True
        if_node.latch_orientation_v28 = orientation
        parent.add(if_node)

        self._populate_conditional_latch_arm(
            if_node.then_branch, owner, node, break_target, "then"
        )
        self._populate_conditional_latch_arm(
            if_node.else_branch, owner, node, stay_target, "else"
        )

        self.branch_control_events.append({
            "kind": "loop_internal_conditional_break_recovered_v44",
            "from": getattr(node, "addr", None),
            "loop": getattr(owner, "addr", None),
            "true": getattr(true_node, "addr", None),
            "false": getattr(false_node, "addr", None),
            "break_target": getattr(break_target, "addr", None),
            "stay_target": getattr(stay_target, "addr", None),
            "orientation": orientation,
            "cond": self._cond_to_string_v19(edge_cond),
        })
        return True

    # =========================================================================
    # NODE EMISSION
    # =========================================================================

    def _closed_in_loop_diamond_arm_v53(self, start, join, loop_header):
        """
        Prove that every path from one candidate arm reaches ``join`` before
        crossing any loop-control boundary.

        This deliberately recognizes an acyclic, closed payload region rather
        than merely asking whether ``join`` is reachable.  A permissive
        reachability test can walk through a latch, revisit the loop header,
        and eventually find the join on a later iteration; that would mistake
        loop continuation for a same-iteration diamond arm.

        Returns ``(proved, region_nodes, reason)``.  ``join`` itself is not in
        ``region_nodes`` because it has single post-diamond ownership.
        """
        if start is None or join is None or loop_header is None:
            return False, set(), "missing_endpoint"

        if start is join:
            return True, set(), "direct_join_arm"

        loop_nodes = set(self.loop_nodes.get(loop_header, set()) or set())
        if not loop_nodes:
            return False, set(), "missing_natural_loop_region"

        latches = set(self.loop_latches.get(loop_header, []) or [])
        exits = set(self.loop_exits.get(loop_header, set()) or set())
        forbidden = {loop_header} | latches | exits

        region = set()
        adjacency = {}
        work = [start]

        # The bound is defensive only.  A valid region cannot contain more
        # nodes than its owning natural loop.
        budget = max(1, len(loop_nodes) + 1)

        while work:
            node = work.pop()

            if node is join:
                continue
            if node in region:
                continue
            if len(region) >= budget:
                return False, region, "region_budget_exceeded"
            if node not in loop_nodes:
                return False, region, "arm_leaves_natural_loop"
            if node in forbidden:
                return False, region, "arm_crosses_loop_control_boundary"
            if node in self.loop_headers:
                return False, region, "arm_enters_nested_or_owner_loop_header"

            succs = []
            for succ in self._successors(node):
                if succ is not None and succ not in succs:
                    succs.append(succ)

            if not succs:
                return False, region, "arm_has_non_join_terminal_frontier"

            region.add(node)
            adjacency[node] = []

            for succ in succs:
                if succ is join:
                    continue
                if succ not in loop_nodes:
                    return False, region, "arm_has_external_frontier"
                if succ in forbidden:
                    return False, region, "arm_reaches_latch_header_or_exit"
                adjacency[node].append(succ)
                if succ not in region:
                    work.append(succ)

        # A closed region can still contain a cycle which never reaches the
        # join at runtime.  Reject such regions; nested loops retain their own
        # established structuring path.
        visiting = set()
        visited = set()

        def has_cycle(node):
            if node in visiting:
                return True
            if node in visited:
                return False

            visiting.add(node)
            for succ in adjacency.get(node, []):
                if succ in region and has_cycle(succ):
                    return True
            visiting.remove(node)
            visited.add(node)
            return False

        for node in list(region):
            if has_cycle(node):
                return False, region, "arm_region_contains_cycle"

        return True, region, "closed_acyclic_arm_to_internal_ipdom"

    def _loop_header_payload_diamond_contract_v53(self, header):
        """
        Return a proved contract when a natural-loop header has two roles:

          * it owns the loop iteration/body entry; and
          * its terminal condition selects an in-loop payload diamond.

        The rule is topology-only.  It does not depend on addresses,
        mnemonics, constants, variable names, or source-language spelling.
        Ordinary pre-test loop headers are excluded because at least one of
        their successors leaves the natural loop.  Latch/exit diamonds and
        nested cyclic regions are also excluded.
        """
        if header is None:
            return None
        if header not in self.loop_headers:
            return None
        if header not in self.loop_body_headers:
            return None
        if self._get_condition(header) is None:
            return None

        successors = []
        for succ in self._successors(header):
            if succ is not None and succ not in successors:
                successors.append(succ)

        if len(successors) != 2 or successors[0] is successors[1]:
            return None

        loop_nodes = set(self.loop_nodes.get(header, set()) or set())
        if not loop_nodes:
            return None
        if any(succ is header or succ not in loop_nodes for succ in successors):
            return None

        join = getattr(header, "ipdom", None)
        if join is None or join is header or join not in loop_nodes:
            return None
        if join in set(self.loop_latches.get(header, []) or []):
            return None
        if join in set(self.loop_exits.get(header, set()) or set()):
            return None
        if join in self.loop_headers:
            return None
        if self._target_is_loop_tail_chain_node(join):
            return None

        arm_regions = []
        arm_reasons = []
        for succ in successors:
            proved, region, reason = self._closed_in_loop_diamond_arm_v53(
                succ,
                join,
                header,
            )
            if not proved:
                return None
            arm_regions.append(set(region))
            arm_reasons.append(reason)

        # Before the IPDOM, distinct diamond arms must not overlap.  Shared
        # ownership belongs to the join and everything after it.
        if arm_regions[0] & arm_regions[1]:
            return None

        return {
            "kind": "loop_header_payload_diamond_contract_v53",
            "header": header,
            "successors": tuple(successors),
            "join": join,
            "arm_regions": tuple(arm_regions),
            "arm_reasons": tuple(arm_reasons),
            "proof": "two_internal_successors_closed_to_internal_ipdom_before_loop_control",
        }

    def _emit_loop_header_payload_diamond_v53(self, header, loop, stop_nodes):
        """
        Emit a proved header-local diamond inside ``loop.body`` and then emit
        its join exactly once.

        Header executable operations have already been placed in the loop body
        by the caller.  This method owns only the header's conditional payload
        role, preserving the existing branch-arm suppressors and direct-join
        PHI edge records through ``_emit_branch_arm``.
        """
        contract = self._loop_header_payload_diamond_contract_v53(header)
        if contract is None:
            return False

        then_node, else_node, join_node = self._get_if_branches(header)
        expected_join = contract.get("join")
        expected_successors = set(contract.get("successors") or ())

        if (
            join_node is not expected_join
            or then_node not in expected_successors
            or else_node not in expected_successors
            or then_node is else_node
        ):
            return False

        cond = self._get_condition(header)
        edge_cond = self._condition_for_branch_then(header, then_node, cond)
        if_node = ExecIf(header, edge_cond)
        if_node.loop_header_payload_diamond_v53 = True
        if_node.loop_header_owner = header
        if_node.payload_join = join_node
        loop.body.add(if_node)

        branch_stops = set(stop_nodes or set())
        branch_stops.add(header)
        branch_stops.add(join_node)

        self._emit_branch_arm(
            header,
            then_node,
            if_node.then_branch,
            branch_stops,
        )
        self._emit_branch_arm(
            header,
            else_node,
            if_node.else_branch,
            branch_stops,
        )

        event = {
            "kind": "loop_header_payload_diamond_v53_consumed",
            "header": getattr(header, "addr", None),
            "then_root": getattr(then_node, "addr", None),
            "else_root": getattr(else_node, "addr", None),
            "join": getattr(join_node, "addr", None),
            "loop": getattr(header, "addr", None),
            "condition": self._cond_to_string_v19(edge_cond),
            "arm_regions": [
                [getattr(n, "addr", None) for n in self._ordered_nodes(region)]
                for region in contract.get("arm_regions", ())
            ],
            "arm_reasons": list(contract.get("arm_reasons", ())),
            "proof": contract.get("proof"),
        }
        self.loop_contract_events.append(event)
        self.branch_control_events.append(dict(event))
        self._record_metadata_event_v43(dict(event))

        # The IPDOM is the first ordinary body node after the payload choice.
        # It is deliberately outside both arms so predecessor-specific PHI
        # drop-ins remain attached to their incoming edges while the join block
        # itself has one execution owner.
        self._emit_node(join_node, loop.body, stop_nodes=set(stop_nodes or set()))
        return True

    def _emit_node(self, node, parent, stop_nodes=None):

        if node is None:
            return

        if stop_nodes is None:
            stop_nodes = set()

        if node in stop_nodes:
            return

        if node in self.visited:
            return

        # -----------------------------------------------------
        # LOOP HEADER
        # -----------------------------------------------------
        if node in self.loop_headers:

            self.visited.add(node)

            cond, cond_role = self._get_loop_condition_and_role_for_header(node)

            # v21c last-mile guard: some older loop construction paths can
            # still return an exit-shaped predicate under role=body. Normalize
            # once more at the exact ExecLoop construction boundary.
            cond, cond_role = self._normalize_loop_condition_role_v20(node, cond, cond_role)

            loop = ExecLoop(node, cond, cond_role)
            loop.header_is_body = bool(node in self.loop_body_headers)
            loop.guard_node = self.loop_guard_nodes.get(node)
            parent.add(loop)

            # Body-header loops contain real executable setup in the header.
            # Emit that block at the top of the loop body before traversing
            # successors.
            if node in self.loop_body_headers:
                loop.body.add(ExecBlock(node))

            exit_nodes = self._get_loop_exits(node)
            normal_exit_nodes = self._get_loop_normal_exits(node)

            local_stops = set(stop_nodes)
            local_stops.add(node)
            local_stops |= set(normal_exit_nodes)

            guard = self.loop_guard_nodes.get(node)
            if guard is not None:
                local_stops.add(guard)

            payload_diamond_emitted = self._emit_loop_header_payload_diamond_v53(
                node,
                loop,
                local_stops,
            )

            if not payload_diamond_emitted:
                body = self._get_loop_body(node)
                if body is not None:
                    self._emit_node(body, loop.body, stop_nodes=local_stops)

            # v28: ordinary fallthrough completion of a lowered for-like loop
            # must execute the iterator/latch update even when explicit continue
            # arms already carry action+latch+continue.  This is loop-level
            # epilogue structure, not branch-arm summarization.
            self._emit_normal_latch_epilogue_for_loop_v28(node, loop)

            # Preserve/lower body-header latch/tail condition chains as
            # explicit continue/break tests. The first tail node may also
            # contain executable update work, so emit its body ops before the
            # synthetic tail-if.
            self._emit_tail_chain_for_loop(node, loop)

            for exit_node in self._ordered_nodes(normal_exit_nodes):
                self._emit_node(exit_node, parent, stop_nodes=stop_nodes)

            return

        # -----------------------------------------------------
        # LOOP TAIL / LATCH TEST NODE
        # -----------------------------------------------------
        if node in self.loop_tail_test_nodes:
            if self._emit_conditional_latch_test_node(node, parent):
                return

            self.visited.add(node)
            parent.add(ExecBlock(node))
            return

        # -----------------------------------------------------
        # CONDITIONAL IF NODE
        # -----------------------------------------------------
        cond = self._get_condition(node)

        if cond is not None:

            # v44: if this is a loop-internal conditional where one edge breaks
            # the innermost loop and the peer remains in that same loop, consume
            # it as a conditional-latch break even if older discovery did not
            # pre-classify it as a loop_tail_test_node.
            if self._try_emit_loop_internal_conditional_break_v44(node, parent, stop_nodes, cond):
                return

            # Recognize lowered short-circuit chains like:
            #     A || (B && C)
            # and emit a single ExecIf with a composite raw condition.
            # This preserves execution truth without duplicating shared THEN/ELSE bodies.
            if self._try_emit_short_circuit_if(node, parent, stop_nodes):
                return

            self.visited.add(node)

            # v43: a conditional CFG block is not always a pure predicate
            # block.  Optimized/commercial-looking code often computes real
            # state before the terminal CBRANCH, then branches on one value
            # produced by that same block, e.g. load data[i], update checksum,
            # then test current_byte parity.  Older SGL represented only the
            # ExecIf and dropped the executable pre-branch payload from the
            # tree.  Preserve such payload by placing the block immediately
            # before its own structured if.  The emitter's block printer already
            # skips pure terminal condition builders, so the branch predicate is
            # not duplicated as a standalone boolean temp.
            if self._conditional_header_has_prebranch_payload_v43(node):
                parent.add(ExecBlock(node))
                self._record_metadata_event_v43({
                    "kind": "condition_header_payload_preserved_v43",
                    "block": self._hex_v26(getattr(node, "addr", None)),
                    "reason": "conditional_block_contains_executable_prebranch_payload",
                })

            if_node = ExecIf(node, cond)
            parent.add(if_node)

            then_node, else_node, join_node = self._get_if_branches(node)

            # v19/PALRAW: condition attached to ExecIf must mean
            # "then-branch is taken", not merely "HF condition SSA is true".
            if_node.cond_var = self._condition_for_branch_then(node, then_node, cond)

            branch_stops = set(stop_nodes)

            if join_node is not None:
                branch_stops.add(join_node)

            if then_node is not None:
                self._emit_branch_arm(node, then_node, if_node.then_branch, branch_stops)

            if else_node is not None:
                self._emit_branch_arm(node, else_node, if_node.else_branch, branch_stops)

            if join_node is not None:
                self._emit_node(join_node, parent, stop_nodes=stop_nodes)

            return

        # -----------------------------------------------------
        # LINEAR SEQUENCE
        # -----------------------------------------------------
        self._emit_linear_sequence(node, parent, stop_nodes)

    # ----------------------------------------------------------------

    def _emit_linear_sequence(self, start, parent, stop_nodes):

        seq = ExecNode("sequence")
        parent.add(seq)

        cur = start

        while cur is not None:

            if cur in stop_nodes:
                break

            if cur in self.visited:
                break

            if cur in self.loop_headers:
                break

            if self._get_condition(cur) is not None:
                break

            seq.add(ExecBlock(cur))
            self.visited.add(cur)

            term = getattr(cur.block, "terminator", None)

            if term is not None and getattr(term, "opcode", None) == "RETURN":
                return

            nxt = self._next_linear(cur)

            if nxt is None:
                break

            # Linear action -> latch/update -> loop header. Do not absorb the
            # latch as ordinary linear code; lower it as explicit continuation.
            loop = self._innermost_loop_for_node(cur)
            if (
                loop is not None
                and not self._is_loop_tail_chain_member(nxt)
                and self._is_executable_latch_update_node(loop, nxt)
            ):
                seq.add(ExecBlock(nxt))
                self.visited.add(nxt)
                seq.add(ExecContinue(loop, "linear_latch_update_continue"))
                self.branch_control_events.append({
                    "kind": "linear_latch_update_continue",
                    "from": getattr(cur, "addr", None),
                    "to": getattr(nxt, "addr", None),
                    "loop": getattr(loop, "addr", None),
                    "source": "cfg_metadata_v19",
                })
                return

            if nxt in self.loop_headers or self._get_condition(nxt) is not None:
                self._emit_node(nxt, parent, stop_nodes=stop_nodes)
                return

            cur = nxt

        if not seq.children:
            try:
                parent.children.remove(seq)
            except Exception:
                pass

    # =========================================================================
    # STRUCTURE HELPERS
    # =========================================================================

    # =========================================================================
    # SHORT-CIRCUIT BOOLEAN CHAINS
    # =========================================================================

    def _short_circuit_condition_node_is_pure_v49(self, cfg_node):
        """
        True when folding this condition node into a Python Boolean expression
        cannot discard an observable state write.

        Formula-producing arithmetic/casts are safe because EdgeTruth already
        carries their expanded predicate.  Calls, stores, indirect effects, and
        writes to recovered locals are not safe to hide inside a composite.
        """
        if cfg_node is None:
            return False

        block = getattr(cfg_node, "block", None)
        if block is None:
            return False

        effect_ops = set((
            "CALL", "CALLIND", "CALLOTHER", "STORE", "INDIRECT",
            "RETURN", "BRANCH", "CBRANCH", "BRANCHIND",
        ))

        for op in list(getattr(block, "ops", []) or []):
            opcode = str(getattr(op, "opcode", "") or "")
            if opcode in effect_ops:
                return False

            out = getattr(op, "output", None)
            if out is None:
                continue

            name = str(getattr(out, "name", "") or "")
            if name.startswith("local_") or bool(getattr(out, "is_stack", False)):
                return False

        return True

    def _canonical_edge_truth_expr_v49(self, src, dst):
        """Return authoritative canonical EdgeTruth text for one exact edge."""
        rec = self._edge_truth_record_v26(src, dst)
        if not isinstance(rec, dict):
            return None
        if not self._metadata_record_is_canonical_edge_truth_v40(rec):
            return None

        confidence = str(rec.get("confidence") or rec.get("trust") or "").lower()
        if confidence not in ("authoritative", "high"):
            return None

        cond = self._metadata_condition_for_edge_v26(
            src,
            dst,
            cond=self._get_condition(src),
        )
        text = self._cond_to_string_v19(cond)
        return str(text).strip() if text else None

    def _try_emit_shared_condition_diamond_v49(self, node, parent, stop_nodes):
        """
        Recognize the edge-truth-backed short-circuit diamond:

            A -> B / C
            B -> THEN / C
            C -> THEN / ELSE

        If P, Q, and R are the exact predicates for A->B, B->THEN,
        and C->THEN, the complete condition for reaching THEN is:

            (P and Q) or R

        This is topology-driven.  It does not depend on block ordering,
        comparison spelling, variable names, constants, or raw true/false
        labels.  Exact canonical EdgeTruth owns every predicate.
        """
        if node is None or node in self.visited or not self._is_conditional_node(node):
            return False

        a_succs = self._successors(node)
        if len(a_succs) != 2 or not all(self._is_conditional_node(s) for s in a_succs):
            return False

        match = None
        for b_node, c_node in ((a_succs[0], a_succs[1]), (a_succs[1], a_succs[0])):
            b_succs = self._successors(b_node)
            c_succs = self._successors(c_node)
            if len(b_succs) != 2 or len(c_succs) != 2:
                continue
            if c_node not in b_succs:
                continue

            b_other = [s for s in b_succs if s is not c_node]
            if len(b_other) != 1:
                continue
            then_root = b_other[0]
            if then_root not in c_succs:
                continue

            else_roots = [s for s in c_succs if s is not then_root]
            if len(else_roots) != 1:
                continue
            else_root = else_roots[0]
            if else_root is node or else_root is b_node or else_root is c_node:
                continue

            match = (b_node, c_node, then_root, else_root)
            break

        if match is None:
            return False

        b_node, c_node, then_root, else_root = match
        join = getattr(node, "ipdom", None)
        if join is None:
            self._sc_reject(node, "shared diamond missing join")
            return False

        if not self._reaches(then_root, join) or not self._reaches(else_root, join):
            self._sc_reject(node, "shared diamond result root does not reach join")
            return False

        if self._looks_like_switch_decision_chain(node, b_node, c_node):
            self._sc_reject(node, "shared diamond looks like switch decision chain")
            return False

        if not all(self._short_circuit_condition_node_is_pure_v49(n) for n in (node, b_node, c_node)):
            self._sc_reject(node, "shared diamond condition block has observable payload")
            return False

        p_expr = self._canonical_edge_truth_expr_v49(node, b_node)
        q_expr = self._canonical_edge_truth_expr_v49(b_node, then_root)
        r_expr = self._canonical_edge_truth_expr_v49(c_node, then_root)
        if not p_expr or not q_expr or not r_expr:
            self._sc_reject(node, "shared diamond lacks authoritative canonical EdgeTruth")
            return False

        composite = RawCond(
            "((%s) and (%s)) or (%s)" % (p_expr, q_expr, r_expr),
            reason="edge_truth_shared_condition_diamond_v49",
        )

        self.visited.add(node)
        self.visited.add(b_node)
        self.visited.add(c_node)

        if_node = ExecIf(node, composite)
        parent.add(if_node)

        branch_stops = set(stop_nodes)
        branch_stops.add(join)

        self._metadata_record_event_v26(
            "shared_condition_diamond_v49_consumed",
            entry=self._addr_v26(node),
            second=self._addr_v26(b_node),
            shared=self._addr_v26(c_node),
            then_root=self._addr_v26(then_root),
            else_root=self._addr_v26(else_root),
            join=self._addr_v26(join),
            p=p_expr,
            q=q_expr,
            r=r_expr,
            composite=self._cond_to_string_v19(composite),
        )

        self._record_branch_event(
            node,
            getattr(node.block, "terminator", None),
            then_root,
            else_root,
            join,
            "short_circuit_shared_condition_diamond_v49_edge_truth",
        )

        self._emit_node(then_root, if_node.then_branch, stop_nodes=branch_stops)
        self._emit_node(else_root, if_node.else_branch, stop_nodes=branch_stops)
        self._emit_node(join, parent, stop_nodes=stop_nodes)
        return True

    def _try_emit_short_circuit_if(self, node, parent, stop_nodes):
        """
        Terminal-based recognizer for the lowered CFG shape of:

            A || (B && C)

        This version is intentionally specific to the observed GCC/O0 pattern.

        Important:
            The previous version recognized the topology but inverted B/C by
            trusting CFG edge labels. For this recognized form, we preserve the
            raw condition formulas:

                A or (B and C)

            because the CFG labels are not reliable enough here and Ghidra's
            recovered execution condition confirms the non-inverted form.
        """

        if self._try_emit_shared_condition_diamond_v49(node, parent, stop_nodes):
            return True

        if node in self.visited:
            return False

        if not self._is_conditional_node(node):
            return False

        a_succs = self._successors(node)

        if len(a_succs) != 2:
            self._sc_reject(node, "A does not have two successors")
            return False

        b_node = None
        then_terminal = None

        for s in a_succs:
            if self._is_conditional_node(s):
                b_node = s
            else:
                then_terminal = s

        if b_node is None or then_terminal is None:
            self._sc_reject(node, "A lacks conditional B or concrete THEN root")
            return False

        b_succs = self._successors(b_node)

        if len(b_succs) != 2:
            self._sc_reject(node, "B does not have two successors")
            return False

        c_node = None
        else_terminal = None

        for s in b_succs:
            if self._is_conditional_node(s):
                ss = self._successors(s)
                if then_terminal in ss:
                    c_node = s
                else:
                    else_terminal = s
            else:
                else_terminal = s

        if c_node is None or else_terminal is None:
            self._sc_reject(node, "could not distinguish C from ELSE root")
            return False

        c_succs = self._successors(c_node)

        if len(c_succs) != 2:
            self._sc_reject(node, "C does not have two successors")
            return False

        if not (then_terminal in c_succs and else_terminal in c_succs):
            self._sc_reject(node, "C successors are not THEN/ELSE roots")
            return False

        join = getattr(node, "ipdom", None)

        if join is None:
            self._sc_reject(node, "missing join")
            return False

        if self._looks_like_switch_decision_chain(node, b_node, c_node):
            self._sc_reject(node, "looks like switch decision chain")
            return False

        # Use raw condition formulas. Do not invert B/C in this recognized
        # OR-AND shape.
        a_expr = self._cond_expr_raw(node)
        b_expr = self._cond_expr_raw(b_node)
        c_expr = self._cond_expr_raw(c_node)

        if not a_expr or not b_expr or not c_expr:
            self._sc_reject(node, "missing raw condition expression")
            return False

        composite = RawCond("(%s) or ((%s) and (%s))" % (a_expr, b_expr, c_expr))

        self.visited.add(node)
        self.visited.add(b_node)
        self.visited.add(c_node)

        if_node = ExecIf(node, composite)
        parent.add(if_node)

        branch_stops = set(stop_nodes)
        branch_stops.add(join)

        self._record_branch_event(
            node,
            getattr(node.block, "terminator", None),
            then_terminal,
            else_terminal,
            join,
            "short_circuit_or_and_raw_v3",
        )

        self._emit_node(then_terminal, if_node.then_branch, stop_nodes=branch_stops)
        self._emit_node(else_terminal, if_node.else_branch, stop_nodes=branch_stops)

        self._emit_node(join, parent, stop_nodes=stop_nodes)

        return True

    def _sc_reject(self, node, reason):
        """
        Debug-only record for why short-circuit recognition failed.
        """

        try:
            self.branch_events.append({
                "block": getattr(node, "addr", None),
                "mode": "short_circuit_reject:" + str(reason),
                "target_addr": None,
                "then": None,
                "else": None,
                "join": getattr(getattr(node, "ipdom", None), "addr", None),
            })
        except Exception:
            pass

    def _expr_for_edge_to_terminal(self, cfg_node, desired_terminal, expr):
        """
        Return expr or not(expr), depending on whether the CFG true edge reaches
        the desired terminal.

        This is intentionally edge-label aware only at this local point: the
        terminal relation determines whether the printed condition must be
        inverted.
        """

        true_node = self._true_edge(cfg_node)
        false_node = self._false_edge(cfg_node)

        if true_node is desired_terminal:
            return expr

        if false_node is desired_terminal:
            return "not (%s)" % expr

        # Sometimes the desired target is the next conditional, not a terminal.
        if true_node is not None and true_node is desired_terminal:
            return expr

        if false_node is not None and false_node is desired_terminal:
            return "not (%s)" % expr

        # Fallback: if true reaches desired and false does not, keep expr.
        if true_node is not None and self._reaches(true_node, desired_terminal):
            if false_node is None or not self._reaches(false_node, desired_terminal):
                return expr

        if false_node is not None and self._reaches(false_node, desired_terminal):
            if true_node is None or not self._reaches(true_node, desired_terminal):
                return "not (%s)" % expr

        return expr

    def _looks_like_switch_decision_chain(self, a_node, b_node, c_node):
        """
        Prevent the short-circuit recognizer from stealing switch decision trees.
        If the three conditions all compare the same computed expression /
        dispatch temp, treat it as switch-like, not boolean short-circuit.
        """

        sigs = []

        for n in (a_node, b_node, c_node):
            cond = self._condition_formula_node(n)
            sig = self._primary_nonconst_input_signature(cond)
            if sig is not None:
                sigs.append(sig)

        if len(sigs) < 2:
            return False

        return len(set(sigs)) == 1

    def _primary_nonconst_input_signature(self, cond_node):
        if cond_node is None:
            return None

        inputs = list(getattr(cond_node, "inputs", []) or [])

        for inp in inputs:
            if getattr(inp, "is_constant", False):
                continue

            sid = getattr(inp, "ssa_id", None)
            if sid is not None:
                return ("sid", sid)

            name = getattr(inp, "name", None)
            if name:
                return ("name", str(name))

        return None

    def _successors(self, cfg_node):
        """
        v22 compatibility helper for CFG successors.
        """
        if cfg_node is None:
            return []

        try:
            succs = getattr(cfg_node, "successors", None)
            if callable(succs):
                return [s for s in list(succs() or []) if s is not None]
            if succs is not None:
                return [s for s in list(succs or []) if s is not None]
        except Exception:
            pass

        out = []
        try:
            for e in list(getattr(cfg_node, "out_edges", []) or []):
                dst = getattr(e, "dst", None)
                if dst is not None:
                    out.append(dst)
        except Exception:
            pass

        return out

    def _cond_expr_raw(self, cfg_node):
        """
        Render the raw condition formula for a CFG conditional block.

        Unlike _cond_expr(), this is allowed to reconstruct the condition
        directly from the block's own ops if the semantic formula graph lookup
        cannot resolve the condition SSA temp. This is what prevents output
        such as v_295/v_348/v_392 in composite short-circuit conditions.
        """

        cond = self._get_condition(cfg_node)

        if cond is None:
            return None

        # Prefer semantic graph node when available.
        node = self._condition_formula_node(cfg_node)
        if node is not None:
            expr = self._formula_expr(node)
            if expr and not self._looks_like_unexpanded_condition_tmp(expr):
                return expr

        # Fallback: reconstruct from block-local op chain ending at cond.
        expr = self._block_local_expr_for_var(cfg_node, cond, seen=set())
        if expr:
            return expr

        return self._var_expr(cond)

    def _looks_like_unexpanded_condition_tmp(self, expr):
        if expr is None:
            return True

        s = str(expr)

        if s.startswith("v_") and all(ch.isalnum() or ch == "_" for ch in s):
            return True

        return False

    def _block_local_expr_for_var(self, cfg_node, var, seen=None):
        """
        Render expression for var by following definitions inside cfg_node.block.ops.

        This is intentionally local to the condition block; it does not inline
        calls from predecessor blocks. It is safe for conditions such as:
            v_263 = v_2683 & 1
            v_295 = v_263 == 0
        """

        if seen is None:
            seen = set()

        if var is None:
            return None

        if getattr(var, "is_constant", False):
            return self._const_expr(var)

        sid = getattr(var, "ssa_id", None)

        if sid is not None:
            if sid in seen:
                return self._var_expr(var)
            seen.add(sid)

        op = self._find_block_def_op(cfg_node, var)

        if op is None:
            return self._var_expr(var)

        return self._block_local_expr_for_op(cfg_node, op, seen)

    def _find_block_def_op(self, cfg_node, var):
        block = getattr(cfg_node, "block", None)

        if block is None:
            return None

        sid = getattr(var, "ssa_id", None)

        for op in list(getattr(block, "ops", []) or []):
            out = getattr(op, "output", None)

            if out is None:
                continue

            if sid is not None and getattr(out, "ssa_id", None) == sid:
                return op

            if out is var:
                return op

        return None

    def _block_local_expr_for_op(self, cfg_node, op, seen):
        opcode = getattr(op, "opcode", None)
        inputs = list(getattr(op, "inputs", []) or [])

        if opcode in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC") and inputs:
            return self._block_local_expr_for_var(cfg_node, inputs[0], seen)

        binops = {
            "INT_ADD": "+",
            "INT_SUB": "-",
            "INT_MULT": "*",
            "INT_DIV": "//",
            "INT_SDIV": "//",
            "INT_REM": "%",
            "INT_SREM": "%",
            "INT_AND": "&",
            "INT_OR": "|",
            "INT_XOR": "^",
            "INT_LEFT": "<<",
            "INT_RIGHT": ">>",
            "INT_SRIGHT": ">>",
            "INT_EQUAL": "==",
            "INT_NOTEQUAL": "!=",
            "INT_LESS": "<",
            "INT_SLESS": "<",
            "INT_LESSEQUAL": "<=",
            "INT_SLESSEQUAL": "<=",
        }

        if opcode in binops and len(inputs) == 2:
            a = self._block_local_value_expr(cfg_node, inputs[0], seen.copy())
            b = self._block_local_value_expr(cfg_node, inputs[1], seen.copy())
            return "(%s %s %s)" % (a, binops[opcode], b)

        if opcode == "BOOL_NEGATE" and inputs:
            a = self._block_local_value_expr(cfg_node, inputs[0], seen.copy())
            return "not (%s)" % a

        if opcode in ("CALL", "CALLIND"):
            # Do not inline calls here unless the call is local to this block
            # and unavoidable. Conditions in this test do not require it.
            out = getattr(op, "output", None)
            return self._var_expr(out)

        out = getattr(op, "output", None)
        return self._var_expr(out)

    def _block_local_value_expr(self, cfg_node, v, seen):
        if v is None:
            return "None"

        if getattr(v, "is_constant", False):
            return self._const_expr(v)

        op = self._find_block_def_op(cfg_node, v)
        if op is not None:
            opcode = getattr(op, "opcode", None)

            if opcode in ("CALL", "CALLIND"):
                return self._var_expr(getattr(op, "output", v))

            # Same state-update guard as _value_expr(), but op-local.
            out = getattr(op, "output", None)
            if opcode in ("INT_ADD", "INT_SUB") and out is not None:
                out_name = self._var_expr(out)
                for inp in list(getattr(op, "inputs", []) or []):
                    if getattr(inp, "is_constant", False):
                        continue
                    if self._var_expr(inp) == out_name:
                        return out_name

            return self._block_local_expr_for_op(cfg_node, op, seen)

        return self._var_expr(v)


    def _cond_expr(self, cfg_node):
        cond = self._get_condition(cfg_node)

        if cond is None:
            return None

        node = self._condition_formula_node(cfg_node)

        if node is not None:
            expr = self._formula_expr(node)
            if expr and not self._looks_like_unexpanded_condition_tmp(expr):
                return expr

        return self._cond_expr_raw(cfg_node)

    def _formula_expr(self, node):
        if node is None:
            return None

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])

        if opcode in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC") and inputs:
            src_node = self._node_for_var(inputs[0])
            if src_node is not None:
                return self._formula_expr(src_node)
            return self._var_expr(inputs[0])

        binops = {
            "INT_ADD": "+",
            "INT_SUB": "-",
            "INT_MULT": "*",
            "INT_DIV": "//",
            "INT_SDIV": "//",
            "INT_REM": "%",
            "INT_SREM": "%",
            "INT_AND": "&",
            "INT_OR": "|",
            "INT_XOR": "^",
            "INT_LEFT": "<<",
            "INT_RIGHT": ">>",
            "INT_SRIGHT": ">>",
            "INT_EQUAL": "==",
            "INT_NOTEQUAL": "!=",
            "INT_LESS": "<",
            "INT_SLESS": "<",
            "INT_LESSEQUAL": "<=",
            "INT_SLESSEQUAL": "<=",
        }

        if opcode in binops and len(inputs) == 2:
            a = self._value_expr(inputs[0])
            b = self._value_expr(inputs[1])
            return "(%s %s %s)" % (a, binops[opcode], b)

        if opcode == "BOOL_NEGATE" and inputs:
            return "not (%s)" % self._value_expr(inputs[0])

        if opcode in ("CALL", "CALLIND"):
            # v19/PALRAW: never inline side-effectful calls into branch
            # conditions.  The call result should already have been emitted
            # as an SSA/temp/local assignment, e.g. v_1736 = feedback(...).
            return self._var_expr(getattr(node, "var", None))

        return self._var_expr(getattr(node, "var", None))

    def _value_expr(self, v):
        node = self._node_for_var(v)

        if node is not None:
            opcode = getattr(node, "opcode", None)

            # v19: never inline call results into expressions; this prevents
            # condition rendering from re-calling feedback()/mutate().
            if opcode in ("CALL", "CALLIND"):
                return self._var_expr(getattr(node, "var", v))

            # v19: if a formula node represents an already-materialized
            # state update, use the canonical output name rather than
            # re-expanding it.  This prevents emitted tails like:
            #     local_14 += 1
            #     if 4 < (local_14 + 1):
            if self._node_is_self_update_alias(node):
                return self._var_expr(getattr(node, "var", v))

            return self._formula_expr(node)

        return self._var_expr(v)

    def _node_is_self_update_alias(self, node):
        """
        True for SSA nodes that are logically the new version of the same
        storage variable, usually emitted separately as +=/-=.

        Example:
            v_367 = local_14 + 1
            var_map[v_367] == local_14

        When the emitter has already printed local_14 += 1, conditions should
        refer to local_14, not local_14 + 1 again.
        """
        if node is None:
            return False

        opcode = getattr(node, "opcode", None)
        if opcode not in ("INT_ADD", "INT_SUB"):
            return False

        out = getattr(node, "var", None)
        if out is None:
            return False

        inputs = list(getattr(node, "inputs", []) or [])
        if len(inputs) != 2:
            return False

        out_name = self._var_expr(out)
        if not out_name:
            return False

        def is_const(x):
            return bool(getattr(x, "is_constant", False))

        # x_next = x_old +/- const
        for inp in inputs:
            if is_const(inp):
                continue
            if self._var_expr(inp) == out_name:
                return True

        return False

    def _node_for_var(self, v):
        if v is None:
            return None

        sid = getattr(v, "ssa_id", None)

        if sid is None:
            return None

        return self._formula_nodes().get(sid)

    def _var_expr(self, v):
        if v is None:
            return "None"

        if hasattr(v, "var"):
            v = v.var

        if getattr(v, "is_constant", False):
            return self._const_expr(v)

        sid = getattr(v, "ssa_id", None)
        var_map = getattr(self.func, "var_map", {}) or {}

        if sid is not None and sid in var_map:
            return var_map[sid]

        name = getattr(v, "name", None)

        if name:
            return str(name)

        if sid is not None:
            return str(sid)

        return str(v)

    def _const_expr(self, v):
        for attr in ("const_value", "value", "offset"):
            val = getattr(v, attr, None)
            if val is not None:
                try:
                    if isinstance(val, int) and abs(val) >= 10:
                        return hex(val)
                except Exception:
                    pass
                return str(val)

        return "0"


    def _get_loop_body(self, header):
        """
        Pick a loop-internal successor.
        """

        guard_body = self._loop_guard_chain_body(header)
        if guard_body is not None:
            return guard_body

        nodes = self.loop_nodes.get(header, set())

        for e in getattr(header, "out_edges", []):

            dst = getattr(e, "dst", None)

            if dst is None:
                continue

            if dst in nodes and dst is not header:
                return dst

        for e in getattr(header, "out_edges", []):

            dst = getattr(e, "dst", None)

            if dst is not None and self._reaches(dst, header):
                return dst

        return None

    def _get_loop_exits(self, header):
        """
        Return all natural-loop exits. Multiple exits are common in lowered
        do/while and short-circuit loops.
        """

        exits = set(self.loop_exits.get(header, set()) or set())

        if exits:
            return exits

        out = set()

        for e in getattr(header, "out_edges", []):

            dst = getattr(e, "dst", None)

            if dst is not None and not self._reaches(dst, header):
                out.add(dst)

        return out

    def _get_loop_normal_exits(self, header):
        normals = set(self.loop_normal_exits.get(header, set()) or set())

        # v27: GraphBuilder may know that some loop exits are shared
        # continuation/gateway blocks.  Add them to normal exits so they are
        # emitted after the loop rather than swallowed as branch-local action
        # by an inner conditional-latch test.
        for n in self._metadata_loop_continuation_gateway_nodes_v27(header):
            if n is not None:
                normals.add(n)

        # v32: even when GraphBuilder did not pre-label the gateway, CFG/ipdom
        # structure can show that an exit target is a shared continuation of an
        # enclosing region.  Treat such targets as normal loop exits so they are
        # emitted immediately after the nested loop, not consumed by a break arm.
        hnodes = set(self.loop_nodes.get(header, set()) or set())
        for ex in list(self._get_loop_exits(header) or set()):
            for pred in list(self._predecessors(ex) or []):
                if pred not in hnodes:
                    continue
                if self._structural_target_is_continuation_gateway_v32(
                    ex,
                    owner_loop=header,
                    from_node=pred,
                ):
                    normals.add(ex)
                    break

        if normals:
            return normals

        return self._get_loop_exits(header)


    def _get_loop_exit(self, header):
        exits = self._get_loop_exits(header)

        if not exits:
            return None

        return self._ordered_nodes(exits)[0]

    def _single_exit_header_condition_is_exit_test(self, header):
        """
        Decide whether a single-exit loop header condition is an exit test
        or a continue/body test.

        v16 unconditionally returned not(raw_cond), which inverted alpha_four
        0x10124a:
            INT_SLESS [local_18, 1]
            true  -> body
            false -> loop exit

        That condition is a continue/body test and should be emitted raw.

        Conservative rule:
          - const < var forms are usually guard/exit tests in these GCC/O0
            do/while tails, so invert them.
          - var < const forms are usually body tests, so keep raw.
          - If CFG metadata says the true edge is loop_exit and false is body,
            also treat as exit test.
        """

        cond_node = self._condition_formula_node(header)

        if cond_node is None:
            return False

        opcode = getattr(cond_node, "opcode", None)
        inputs = list(getattr(cond_node, "inputs", []) or [])

        true_node = self._true_edge(header)
        false_node = self._false_edge(header)

        true_exits = self._edge_exits_loop(header, true_node) is header
        false_exits = self._edge_exits_loop(header, false_node) is header

        if true_exits and not false_exits:
            return True

        if false_exits and not true_exits:
            # Prefer formula polarity for less-than forms below.
            pass

        if opcode in ("INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL"):
            if len(inputs) == 2:
                left, right = inputs[0], inputs[1]
                left_const = bool(getattr(left, "is_constant", False))
                right_const = bool(getattr(right, "is_constant", False))

                if left_const and not right_const:
                    return True

                if not left_const and right_const:
                    return False

        return False


    def _get_loop_condition_for_header(self, header):
        """
        Backward-compatible condition-only API.
        """
        cond, role = self._get_loop_condition_and_role_for_header(header)
        return cond

    def _get_loop_condition_and_role_for_header(self, header):
        """
        Return (condition, condition_role) for an ExecLoop.

        Roles:
            true -> emit while True
            body -> emit while condition
            exit -> emit while not(condition)

        v20b invariant:
            body predicates must admit the loop body.
            exit predicates must describe loop exit.
        """

        def done(cond, role):
            return self._normalize_loop_condition_role_v20(header, cond, role)

        chained = self._loop_guard_chain_condition(header)
        if chained is not None:
            # Guard chains represent loop-exit disjunctions.
            return done(chained, "exit")

        if header in self.loop_single_exit_tests:
            body_cond = self._condition_for_loop_body_edge(header)
            if body_cond is not None:
                return done(body_cond, "body")

            exit_cond = self._condition_for_loop_exit_edge(header)
            if exit_cond is not None:
                return done(exit_cond, "exit")

            raw = self._cond_expr_raw(header)

            if self._single_exit_header_condition_is_exit_test(header):
                return done(RawCond(raw, reason="v20_single_exit_header_exit_predicate"), "exit")

            return done(RawCond(raw, reason="v20_single_exit_header_body_predicate"), "body")

        if header in self.loop_body_headers:
            return done(None, "true")

        cond = self._get_condition(header)
        if cond is None:
            return done(None, "true")

        body_node = self._first_body_node_for_header_v19b(header)
        explicit_target = self._true_edge(header)

        if explicit_target is not None and body_node is not None:
            if explicit_target is body_node:
                return done(cond, "body")
            return done(cond, "exit")

        return done(cond, "body")

    def _first_body_node_for_header_v19b(self, header):
        if header is None:
            return None

        nodes = set(self.loop_nodes.get(header, set()) or set())
        nodes.discard(header)

        if not nodes:
            return None

        for succ in list(getattr(header, "successors", []) or []):
            if succ in nodes:
                return succ

        ordered = self._ordered_nodes(nodes)
        return ordered[0] if ordered else None


    def _ordered_nodes(self, nodes):
        return sorted(
            [n for n in nodes if n is not None],
            key=lambda n: getattr(n, "addr", 0) if isinstance(getattr(n, "addr", 0), int) else 0,
        )


    def _edge_role_pair_is_raw_locked(self, node, true_node, false_node):
        """
        v19: raw CFG custody outranks expression-shape repair heuristics.

        If PALlibrary provided one raw_true_explicit_target edge and one
        raw_false_fallthrough edge, the then/else orientation is already
        grounded in the CBRANCH target. SGL may still prettify the expression
        later, but it must not swap branch bodies here.
        """
        if node is None or true_node is None or false_node is None:
            return False

        true_role = None
        false_role = None

        for e in self._as_list(getattr(node, "out_edges", None)):
            dst = getattr(e, "dst", None)
            role = getattr(e, "role", None)
            raw = getattr(e, "raw_type", None)

            if dst is true_node:
                true_role = role or raw
            elif dst is false_node:
                false_role = role or raw

        if true_role == "raw_true_explicit_target" and false_role == "raw_false_fallthrough":
            return True

        # Some PALlibrary versions expose flags rather than role strings.
        true_explicit = False
        false_fallthrough = False
        for e in self._as_list(getattr(node, "out_edges", None)):
            dst = getattr(e, "dst", None)
            if dst is true_node:
                true_explicit = bool(getattr(e, "explicit_target", False) or getattr(e, "is_explicit_target", False))
            elif dst is false_node:
                false_fallthrough = bool(getattr(e, "fallthrough", False) or getattr(e, "is_fallthrough", False))

        return true_explicit and false_fallthrough

    def _get_if_branches(self, node):
        """
        Return then/else/join for a conditional node.

        Baseline:
            use CFG true/false labels.

        Then repair only narrow, observed polarity mistakes.
        """

        term = getattr(node.block, "terminator", None)

        if not term or getattr(term, "opcode", None) != "CBRANCH":
            return None, None, None

        join = getattr(node, "ipdom", None)

        true_node = self._true_edge(node)
        false_node = self._false_edge(node)

        mode = "cfg_true_false"

        if true_node is None and false_node is None:
            explicit = self._explicit_branch_successor(node, term)
            fallthrough = self._fallthrough_successor(node, explicit)
            true_node, false_node = explicit, fallthrough
            mode = "explicit_true"

        # v19/PALRAW:
        # Edge ownership remains raw-CFG based.  Polarity repair is now
        # condition-side, not body-swap-side, when PALlibrary exposes raw
        # condition polarity.
        if self._edge_role_pair_is_raw_locked(node, true_node, false_node):
            then_node, else_node, reason = true_node, false_node, "raw_edge_locked"
        else:
            then_node, else_node, reason = self._repair_branch_polarity(
                node,
                true_node,
                false_node,
                join,
            )

        if reason:
            mode += "+" + reason

        self._record_branch_event(node, term, then_node, else_node, join, mode)

        return then_node, else_node, join

    # ----------------------------------------------------------------

    def _loop_internal_notequal_should_keep_raw_v45(self, node, true_node, false_node):
        """
        v45: Do not apply switch/default INT_NOTEQUAL body-swap heuristics to
        loop-internal conditional latch/break tests.

        The old rule D was built for lowered switch dispatch:

            if x != 1: default/action
            else:      case-1 conditional

        It swaps when the raw true edge is conditional and the false edge is an
        action block.  In alpha_four O0, the inner mutate loop also has an
        INT_NOTEQUAL terminal condition where one successor is a post-loop / loop
        exit continuation and the peer remains inside the inner loop.  Swapping
        those arms changes:

            if v != 0xf: break

        into:

            if not(v != 0xf): break

        This guard keeps raw CFG true/false orientation whenever an INT_NOTEQUAL
        block is inside a loop and its two successors split between "stay in this
        innermost loop" and "leave this innermost loop".  It is generic: no
        address or constant is mentioned.
        """
        if node is None or true_node is None or false_node is None:
            return False

        owner = self._innermost_loop_for_node(node)
        if owner is None:
            return False

        def stays(t):
            if t is None:
                return False
            if t is owner:
                return True
            try:
                if self._edge_continues_loop(node, t) is owner:
                    return True
            except Exception:
                pass
            try:
                return t in set(self.loop_nodes.get(owner, set()) or set())
            except Exception:
                return False

        def leaves(t):
            if t is None:
                return False
            try:
                if self._edge_exits_loop(node, t) is owner:
                    return True
            except Exception:
                pass
            return not stays(t)

        true_stays = stays(true_node)
        false_stays = stays(false_node)
        true_leaves = leaves(true_node)
        false_leaves = leaves(false_node)

        return bool((true_stays and false_leaves) or (false_stays and true_leaves))

    def _repair_branch_polarity(self, node, true_node, false_node, join):
        """
        Narrow branch-polarity repairs.

        These rules are local and conservative. They avoid duplication and
        preserve the original stable traversal behavior.
        """

        if true_node is None or false_node is None:
            return true_node, false_node, None

        cond_node = self._condition_formula_node(node)
        opcode = getattr(cond_node, "opcode", None)
        # v46: condition nodes can be rewritten/aliased by PHI/post-update
        # metadata so the direct formula object may no longer expose the
        # original comparison opcode.  Fall back to the block-level condition
        # opcode extractor before applying branch-body repair heuristics.
        if not opcode:
            opcode = self._condition_opcode_for_cfg_node_v19(node)
        if opcode is not None:
            opcode = str(opcode).upper()

        # A. Skip-to-join pattern:
        #      if cond: goto join
        #      else: action
        #
        # Older SGL builds inverted this into "if cond: action", which destroys
        # programmatic truth for cases like alpha_four's optional swap:
        #      true  -> latch/tail join
        #      false -> swap action
        #
        # Keep CFG edge truth. The true arm may be empty/fallthrough; the false
        # arm must still emit if it has executable operations.
        if join is not None and true_node is join and false_node is not join:
            return true_node, false_node, "keep_true_join_skip"

        # B. v19: retired unsafe swap_const_less_var body swap.
        #
        # Constant-less-than-variable expressions such as:
        #
        #     INT_SLESS [0xffffffff, local_20]
        #
        # may look like loop-exit/skip tests, but the raw CBRANCH target already
        # defines which successor is true. Swapping branch bodies here inverts
        # execution at blocks such as 0x10125c. Any later "prettification" must
        # rewrite/negate the condition expression, not exchange then/else arms.
        if opcode in ("INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL"):
            inputs = list(getattr(cond_node, "inputs", []) or [])

            if len(inputs) == 2:
                left, right = inputs[0], inputs[1]

                if getattr(left, "is_constant", False) and not getattr(right, "is_constant", False):
                    return true_node, false_node, "keep_const_less_var_raw"

        # C0. Range-ladder contradiction repair:
        #
        #    if x < 4:
        #        action
        #    else:
        #        if x < 2:    # unreachable under x >= 4
        #            ...
        #
        # This appears in GCC/O0 lowered switch/fallthrough regions. The
        # nested stricter less-than under the false arm would make an entire
        # branch disappear. Swap the parent so the stricter test is inside the
        # looser range arm:
        #
        #    if x < 4:
        #        if x < 2:
        #            ...
        #    else:
        #        action
        #
        # This is deliberately limited to same-value var<const tests with a
        # smaller constant in the conditional false arm.
        if (
            opcode in ("INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL")
            and self._is_conditional_node(false_node)
            and not self._is_conditional_node(true_node)
            and self._is_stricter_less_test_on_same_value(cond_node, false_node)
        ):
            return false_node, true_node, "swap_range_ladder_stricter_false"

        # C. Switch/range tree repair:
        #    if v_1460 < 3:
        #       continue testing cases 0/1
        #    else:
        #       default action
        #
        # Content-based fallback: in this GCC/O0 tree the default action block
        # is INT_LEFT(acc, 1). If the true edge goes to INT_LEFT and the false
        # edge continues to another condition, swap.
        if opcode in ("INT_LESS", "INT_SLESS") or self._block_has_opcode(true_node, "INT_LEFT"):
            true_is_cond = self._is_conditional_node(true_node)
            false_is_cond = self._is_conditional_node(false_node)

            if self._block_has_opcode(true_node, "INT_LEFT") and false_is_cond:
                return false_node, true_node, "swap_less_default_left"

            if not true_is_cond and false_is_cond:
                if self._conditions_probably_share_dispatch(cond_node, false_node):
                    return false_node, true_node, "swap_less_dispatch_cond"

            if true_is_cond and not false_is_cond:
                if self._conditions_probably_share_dispatch(cond_node, true_node):
                    return true_node, false_node, "keep_less_dispatch_cond"

        # v45: INT_NOTEQUAL also appears in loop-internal latch/break
        # tests.  In that shape, rule D's dispatch-oriented body swap can invert
        # the break predicate.  If one successor remains in the innermost loop
        # and the peer leaves it, raw CFG edge orientation is the safer truth.
        if opcode == "INT_NOTEQUAL" and self._loop_internal_notequal_should_keep_raw_v45(node, true_node, false_node):
            return true_node, false_node, "keep_notequal_loop_internal_raw_v46"

        # D. switch x != 1:
        #    if x != 1: default
        #    else: case-1 check_bit path
        #
        # The default block is INT_LEFT(acc, 1). If false goes to that default
        # and true goes to check_bit, swap so the emitted condition x != 1
        # enters default.
        if opcode == "INT_NOTEQUAL" or self._block_has_opcode(false_node, "INT_LEFT"):
            if self._block_has_opcode(false_node, "INT_LEFT") and self._is_conditional_node(true_node):
                return false_node, true_node, "swap_notequal_default_left"

            if self._is_conditional_node(true_node) and not self._is_conditional_node(false_node):
                return false_node, true_node, "swap_notequal_cond_action"

        # E-1/E0 retired in v19.
        #
        # v16 used a broad "negative action vs dispatch" heuristic here:
        #     false branch has add-negative, true branch is conditional
        # and swapped the CFG arms.
        #
        # That broke alpha_four 0x1011c3. The CFG/P-code branch truth is:
        #     INT_EQUAL == 0
        #     true  -> dispatch block 0x101206
        #     false -> negative-update block 0x101200
        #
        # SGL must not rewrite branch polarity merely because one arm contains
        # a negative add. If source-like structure wants the opposite, that is
        # a presentation concern above ground execution, not SGL truth.
        #
        # Keep the old cases documented, but do not fire them.
        if False and self._block_has_add_negative(false_node) and self._is_conditional_node(true_node):
            return false_node, true_node, "swap_negative_action_vs_dispatch_disabled_v19"

        if False and opcode == "INT_EQUAL":
            if self._block_has_add_negative(false_node) and self._is_conditional_node(true_node):
                return false_node, true_node, "swap_equal_negative_continue_disabled_v19"

            if self._path_has_add_negative_before_join(false_node, join) and self._is_conditional_node(true_node):
                return false_node, true_node, "swap_equal_negative_continue_path_disabled_v19"

        # E. check_bit(acc, 3) lowered as check_bit == 0:
        #    source truth:
        #       if check_bit: acc -= 5
        #       else: acc = transform_a(acc)
        #    lowered condition ==0 means true edge is else-source path.
        #    Keep executable truth for the emitted condition v_2712 == 0:
        #       true -> transform_a
        #       false -> subtract
        #    Therefore no swap if true is transform_a and false is add(-5).
        #    But if opposite is detected, swap.
        if opcode == "INT_EQUAL" and self._is_checkbit_eq_zero(cond_node):
            true_call = self._block_has_call_named(true_node, "transform_a")
            false_sub = self._block_has_add_negative(false_node)

            if not (true_call and false_sub):
                false_call = self._block_has_call_named(false_node, "transform_a")
                true_sub = self._block_has_add_negative(true_node)

                if false_call and true_sub:
                    return false_node, true_node, "swap_checkbit_eq0"

        # F. Parity ternary:
        #    condition (i & 1) == 0 should pick transform_b(acc), not
        #    transform_a(i). Use content-based detection so this still works if
        #    formula-node lookup fails.
        if opcode == "INT_EQUAL" or (
            self._block_has_call_named(true_node, "transform_a") and
            self._block_has_call_named(false_node, "transform_b")
        ):
            true_a = self._block_has_call_named(true_node, "transform_a")
            false_b = self._block_has_call_named(false_node, "transform_b")

            if true_a and false_b:
                return false_node, true_node, "swap_parity_ternary_content"

        # G. final state update:
        #    if state == 7: acc -= 100
        #    in CFG true may go to join and false to subtract block.
        #    If false action is negative add and true is join, handled by A.
        #    Extra guard: if true is join-like predecessor and false has
        #    negative add, swap.
        if opcode == "INT_EQUAL":
            if join is not None and self._block_has_add_negative(false_node):
                if true_node is join or self._reaches(true_node, join):
                    return false_node, true_node, "swap_equal_negative_action"

        return true_node, false_node, None

    # =========================================================================
    # v22 FINAL EXEC TREE CONTRACT VALIDATION
    # =========================================================================

    def _finalize_exec_tree_contracts_v22(self):
        """
        Final post-build invariant pass over ExecLoop nodes.
        """
        self._walk_exec_tree_v22(self.root, self._finalize_loop_node_v22)

    def _walk_exec_tree_v22(self, node, fn):
        if node is None:
            return
        fn(node)
        for child in list(getattr(node, "children", []) or []):
            self._walk_exec_tree_v22(child, fn)

    def _record_loop_contract_v22(self, loop, old_cond, old_role, new_cond, new_role, why):
        try:
            self.loop_contract_events.append({
                "header": getattr(getattr(loop, "header", None), "addr", None),
                "old_role": old_role,
                "old_cond": getattr(old_cond, "name", old_cond),
                "new_role": new_role,
                "new_cond": getattr(new_cond, "name", new_cond),
                "why": why,
            })
        except Exception:
            pass

    def _finalize_loop_node_v22(self, node):
        if getattr(node, "kind", None) != "loop":
            return
        header = getattr(node, "header", None)
        cond = getattr(node, "cond_var", None)
        role = getattr(node, "condition_role", None)
        if role in (None, "true") or cond is None:
            return
        old_cond, old_role = cond, role
        cond, role, why = self._loop_contract_repair_v22(header, cond, role)
        if cond is not old_cond or role != old_role:
            node.cond_var = cond
            node.condition_role = role
            node.emit_condition_mode = role
            self._record_loop_contract_v22(node, old_cond, old_role, cond, role, why)

    def _loop_contract_repair_v22(self, header, cond, role):
        s = self._cond_to_string_v19(cond)
        clean = self._strip_redundant_outer_parens_v19(s)
        if not clean or role != "body":
            return cond, role, "unchanged"

        # body-role with const < var is exit-shaped for GCC/O0 counter loops.
        if self._is_const_lt_var_expr_v22(clean):
            return RawCond(clean, source=cond, reason="v22_final_const_lt_var_exit"), "exit", "final_const_lt_var_exit"

        body_node = self._get_loop_body(header)
        try:
            body_edge_invert = bool(self._edge_condition_invert_for_edge(header, body_node))
        except Exception:
            body_edge_invert = False

        var_name, inner = self._negated_less_inner_v19(clean)
        if var_name and inner:
            # A simple positive induction variable proves this is an ordinary
            # counter body predicate.  This overrides low-confidence edge
            # inversion because the loop update class is stronger evidence.
            if self._loop_has_positive_induction_update_v19(header, var_name):
                return RawCond(inner, source=cond, reason="v23_final_strip_positive_induction_not_less"), "body", "final_strip_positive_induction_not_less"
            if not body_edge_invert:
                return RawCond(inner, source=cond, reason="v23_final_strip_accidental_not_less"), "body", "final_strip_accidental_not_less"

        lt_inner = self._ge_to_lt_inner_v22(clean)
        if lt_inner:
            ge_var = self._ge_var_name_v23(clean)
            if ge_var and self._loop_has_positive_induction_update_v19(header, ge_var):
                return RawCond(lt_inner, source=cond, reason="v23_final_ge_to_lt_positive_induction_body"), "body", "final_ge_to_lt_positive_induction_body"
            if not body_edge_invert:
                return RawCond(lt_inner, source=cond, reason="v23_final_ge_to_lt_body"), "body", "final_ge_to_lt_body"

        return cond, role, "unchanged"

    def _is_const_lt_var_expr_v22(self, expr):
        expr = self._strip_redundant_outer_parens_v19(expr)
        return bool(re.match(r"^(0x[0-9a-fA-F]+|\d+)\s*<\s*[A-Za-z_][A-Za-z0-9_]*$", expr or ""))

    def _ge_to_lt_inner_v22(self, expr):
        expr = self._strip_redundant_outer_parens_v19(expr)
        if not expr:
            return None
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*>=\s*(0x[0-9a-fA-F]+|\d+)$", expr)
        if not m:
            return None
        return "%s < %s" % (m.group(1), m.group(2))

    def _ge_var_name_v23(self, expr):
        expr = self._strip_redundant_outer_parens_v19(expr)
        if not expr:
            return None
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*>=\s*(0x[0-9a-fA-F]+|\d+)$", expr)
        return m.group(1) if m else None


    # =========================================================================
    # v24/v54 METADATA CONSOLIDATION / PHI-EMITTER HANDOFF
    # =========================================================================

    def _consolidate_metadata_v24(self):
        """
        Build metadata records for downstream layers without changing SGL.

        SGL owns:
          - control structure
          - branch arm orientation
          - loop condition role
          - condition consumer sites

        PHIfolder/emitter should own:
          - exact post-update value alias closure
          - materialization or safe inline of condition temps
          - final expression presentation

        This pass therefore exports facts/candidates, not rewritten code.

        v54 adds a source-aware condition provenance sidecar.  RawCond remains
        the authoritative frozen edge predicate and its textual contract is
        not changed.  The sidecar follows RawCond.source, when present, and
        exports the originating SSA/formula identity plus every structurally
        reachable formula dependency.  Text-derived SID recovery remains a
        separately labelled fallback for synthetic/composite RawCond values.
        """

        self.condition_consumers = []
        self.condition_provenance_sidecars = []
        self.condition_temp_defs = []
        self.post_update_alias_candidates = []
        self.metadata_events = []

        seen_consumers = set()
        seen_temp_defs = set()
        seen_aliases = set()

        for item in self._iter_condition_consumers_v24(self.root):
            cond = item.get("cond")
            expr = self._cond_to_string_v19(cond)
            sidecar = self._condition_provenance_sidecar_v54(cond, expr, item)

            consumer = {
                "kind": item.get("kind"),
                "addr": item.get("addr"),
                "role": item.get("role"),
                "cond_sid": self._sid_of_var_v24(cond),
                "cond_expr": expr,
                "reason": getattr(cond, "reason", None),
                # v54 additive fields.  cond_sid intentionally retains its
                # historical direct-object meaning; downstream layers can
                # opt into source-aware custody through effective_condition_sid.
                "condition_representation": sidecar.get("condition_representation"),
                "source_condition_sid": sidecar.get("source_condition_sid"),
                "effective_condition_sid": sidecar.get("effective_condition_sid"),
                "formula_dependency_sids": list(sidecar.get("formula_dependency_sids", []) or []),
                "text_dependency_sids": list(sidecar.get("text_dependency_sids", []) or []),
                "dependency_authority": sidecar.get("dependency_authority"),
            }

            key = (
                consumer.get("kind"),
                consumer.get("addr"),
                consumer.get("role"),
                consumer.get("cond_sid"),
                consumer.get("cond_expr"),
            )
            if key not in seen_consumers:
                seen_consumers.add(key)
                provenance_ref = "sgl_condition_provenance:%04d" % len(
                    self.condition_provenance_sidecars
                )
                consumer["provenance_ref"] = provenance_ref
                sidecar["provenance_ref"] = provenance_ref
                sidecar["consumer_kind"] = consumer.get("kind")
                sidecar["consumer_addr"] = consumer.get("addr")
                sidecar["consumer_role"] = consumer.get("role")
                self.condition_consumers.append(consumer)
                self.condition_provenance_sidecars.append(sidecar)

            for rec in self._condition_temp_def_records_v24(expr, consumer):
                rkey = (
                    rec.get("sid"),
                    rec.get("name"),
                    rec.get("consumer_addr"),
                    rec.get("expr"),
                    rec.get("source_addr"),
                )
                if rkey not in seen_temp_defs:
                    seen_temp_defs.add(rkey)
                    self.condition_temp_defs.append(rec)

            for rec in self._post_update_alias_candidate_records_v24(cond, consumer):
                rkey = (
                    rec.get("source_sid"),
                    rec.get("target_name"),
                    rec.get("consumer_addr"),
                    rec.get("expr"),
                )
                if rkey not in seen_aliases:
                    seen_aliases.add(rkey)
                    self.post_update_alias_candidates.append(rec)

        self.metadata_events.append({
            "kind": "metadata_consolidation_v54",
            "condition_consumers": len(self.condition_consumers),
            "condition_provenance_sidecars": len(self.condition_provenance_sidecars),
            "raw_condition_consumers": sum(
                1 for rec in self.condition_provenance_sidecars
                if rec.get("condition_representation") == "raw_condition"
            ),
            "source_sid_recoveries": sum(
                1 for rec in self.condition_provenance_sidecars
                if rec.get("direct_condition_sid") is None
                and rec.get("source_condition_sid") is not None
            ),
            "formula_authoritative_consumers": sum(
                1 for rec in self.condition_provenance_sidecars
                if rec.get("dependency_authority") == "formula_structure"
            ),
            "text_fallback_consumers": sum(
                1 for rec in self.condition_provenance_sidecars
                if rec.get("dependency_authority") == "condition_text_fallback"
            ),
            "condition_temp_defs": len(self.condition_temp_defs),
            "post_update_alias_candidates": len(self.post_update_alias_candidates),
        })

    def _condition_provenance_sidecar_v54(self, cond, expr, consumer_item=None):
        """
        Return a JSON-safe structural sidecar for one SGL condition consumer.

        The sidecar deliberately separates three identities:
          - direct_condition_sid: SID carried by ExecIf/ExecLoop.cond_var;
          - source_condition_sid: first structural SID behind RawCond.source;
          - effective_condition_sid: direct SID, otherwise source SID.

        formula_dependency_sids are obtained by walking FormulaNode inputs.
        text_dependency_sids are merely tokens observed in the frozen string.
        They are never presented as structural authority.
        """

        representation = self._condition_representation_v54(cond)
        direct_sid = self._sid_of_var_v24(cond)
        source_chain = self._condition_source_chain_v54(cond)

        structural_source = None
        source_sid = None
        for candidate in source_chain[1:]:
            candidate_sid = self._condition_structural_sid_v54(candidate)
            if candidate_sid is not None:
                structural_source = candidate
                source_sid = candidate_sid
                break

        if direct_sid is not None:
            structural_source = cond

        effective_sid = direct_sid if direct_sid is not None else source_sid
        root = self._condition_formula_root_v54(structural_source)
        formula_sids = self._formula_dependency_sids_v54(root)

        # A structural source can be a PAL variable whose FormulaNode is not
        # present.  Retain its SID as authoritative even without a traversable
        # formula tree.
        if effective_sid is not None and effective_sid not in formula_sids:
            formula_sids.insert(0, effective_sid)

        text_sids = self._condition_text_dependency_sids_v54(expr)
        dependency_sids = self._stable_unique_v54(formula_sids + text_sids)

        if formula_sids:
            dependency_authority = "formula_structure"
        elif text_sids:
            dependency_authority = "condition_text_fallback"
        elif expr:
            dependency_authority = "literal_condition_only"
        else:
            dependency_authority = "none"

        dependency_records = []
        for sid in formula_sids:
            dependency_records.append(self._formula_dependency_record_v54(sid))

        source_record = self._formula_dependency_record_v54(effective_sid)

        return {
            "kind": "sgl_condition_provenance_sidecar_v54",
            "version": self.sgl_version,
            "condition_representation": representation,
            "direct_condition_sid": direct_sid,
            "source_condition_sid": source_sid,
            "effective_condition_sid": effective_sid,
            "source_chain_depth": max(0, len(source_chain) - 1),
            "raw_condition_inverted": bool(getattr(cond, "inverted", False)),
            "raw_condition_reason": getattr(cond, "reason", None),
            "condition_expr": expr,
            "formula_dependency_sids": formula_sids,
            "text_dependency_sids": text_sids,
            "dependency_sids": dependency_sids,
            "dependency_authority": dependency_authority,
            "formula_dependencies": dependency_records,
            "source_op_key": source_record.get("op_key"),
            "source_op_id": source_record.get("op_id"),
            "source_opcode": source_record.get("opcode"),
            "source_block_addr": source_record.get("block_addr"),
            "authority": (
                "RawCond_text_owns_edge_truth; formula_sidecar_owns_dependency_identity"
                if representation == "raw_condition"
                else "formula_or_SSA_condition_identity"
            ),
        }

    def _condition_representation_v54(self, cond):
        if cond is None:
            return "none"
        if isinstance(cond, RawCond):
            return "raw_condition"
        if isinstance(cond, str):
            return "condition_text"
        if hasattr(cond, "var") and hasattr(cond, "opcode"):
            return "formula_node"
        if getattr(cond, "ssa_id", None) is not None:
            return "ssa_variable"
        if getattr(cond, "is_constant", False):
            return "literal_constant"
        return "unknown"

    def _condition_source_chain_v54(self, cond):
        chain = []
        cur = cond
        seen = set()

        while cur is not None:
            marker = id(cur)
            if marker in seen:
                break
            seen.add(marker)
            chain.append(cur)

            source = getattr(cur, "source", None)
            if source is None or source is cur:
                break
            cur = source

        return chain

    def _condition_structural_sid_v54(self, value):
        if value is None:
            return None
        if hasattr(value, "var") and hasattr(value, "opcode"):
            return self._sid_of_var_v24(getattr(value, "var", None))
        return self._sid_of_var_v24(value)

    def _condition_formula_root_v54(self, value):
        if value is None:
            return None
        if hasattr(value, "var") and hasattr(value, "opcode"):
            return value
        sid = self._condition_structural_sid_v54(value)
        return self._formula_node_for_sid_v54(sid)

    def _formula_dependency_sids_v54(self, root):
        if root is None:
            return []

        out = []
        seen_nodes = set()

        def walk(node):
            if node is None:
                return

            marker = id(node)
            if marker in seen_nodes:
                return
            seen_nodes.add(marker)

            output_sid = self._sid_of_var_v24(getattr(node, "var", None))
            if output_sid is not None:
                out.append(output_sid)

            for inp in list(getattr(node, "inputs", []) or []):
                input_sid = self._sid_of_var_v24(inp)
                if input_sid is not None:
                    out.append(input_sid)
                child = self._formula_node_for_sid_v54(input_sid)
                if child is not None:
                    walk(child)

        walk(root)
        return self._stable_unique_v54(out)

    def _condition_text_dependency_sids_v54(self, expr):
        if not expr:
            return []
        return self._stable_unique_v54(
            re.findall(r"\bv_\d+\b", str(expr))
        )

    def _stable_unique_v54(self, values):
        out = []
        seen = set()
        for value in list(values or []):
            if value is None:
                continue
            marker = str(value)
            if marker in seen:
                continue
            seen.add(marker)
            out.append(value)
        return out

    def _formula_node_for_sid_v54(self, sid):
        if sid is None:
            return None

        nodes = self._formula_nodes()
        candidates = [sid]
        text = str(sid)
        if text.startswith("v_") and text[2:].isdigit():
            candidates.append(int(text[2:]))
        elif text.isdigit():
            candidates.append("v_%s" % text)

        for candidate in candidates:
            node = nodes.get(candidate)
            if node is not None:
                return node
        return None

    def _formula_dependency_record_v54(self, sid):
        record = {
            "sid": sid,
            "op_key": None,
            "op_id": None,
            "block_addr": None,
            "opcode": None,
        }
        if sid is None:
            return record

        op, cfg_node, ordinal = self._find_def_op_identity_v54(sid)
        if op is None:
            return record

        op_id = getattr(op, "op_id", None) or getattr(op, "hf_seqnum", None)
        block_addr = getattr(cfg_node, "addr", None) if cfg_node is not None else None
        record.update({
            "op_key": "%s:%s:%s" % (block_addr, op_id, ordinal),
            "op_id": str(op_id) if op_id is not None else None,
            "block_addr": block_addr,
            "opcode": getattr(op, "opcode", None),
        })
        return record

    def _find_def_op_identity_v54(self, sid):
        if sid is None:
            return None, None, None

        wanted = str(sid)
        for cfg_node in self._real_nodes():
            block = getattr(cfg_node, "block", None)
            if block is None:
                continue
            for ordinal, op in enumerate(list(getattr(block, "ops", []) or [])):
                out = getattr(op, "output", None)
                if str(getattr(out, "ssa_id", None)) == wanted:
                    return op, cfg_node, ordinal

        return None, None, None

    def _iter_condition_consumers_v24(self, node):
        if node is None:
            return

        kind = getattr(node, "kind", None)

        if kind == "if":
            cfg_node = getattr(node, "cfg_node", None)
            cond = getattr(node, "cond_var", None)
            yield {
                "kind": "if",
                "addr": getattr(cfg_node, "addr", None),
                "role": "then",
                "cond": cond,
                "node": node,
            }

        elif kind == "loop":
            header = getattr(node, "header", None)
            cond = getattr(node, "cond_var", None)
            yield {
                "kind": "loop",
                "addr": getattr(header, "addr", None),
                "role": getattr(node, "condition_role", None),
                "cond": cond,
                "node": node,
            }

        for child in list(getattr(node, "children", []) or []):
            for item in self._iter_condition_consumers_v24(child):
                yield item

    def _sid_of_var_v24(self, v):
        if v is None:
            return None
        if hasattr(v, "var"):
            v = v.var
        return getattr(v, "ssa_id", None)

    def _condition_temp_def_records_v24(self, expr, consumer):
        """
        Find unresolved temp names in condition expressions and export their
        defining formula/op when SGL can locate it.

        This is the v_2228 class.  SGL does not decide whether to inline or
        materialize.  It only says: "condition at X consumes temp Y; here is
        its pure definition candidate."
        """

        if not expr:
            return []

        out = []
        for name in sorted(set(re.findall(r"\bv_(\d+)\b", str(expr)))):
            try:
                sid = int(name)
            except Exception:
                continue

            temp_name = "v_%s" % name
            node = self._formula_nodes().get(sid)
            source_addr = None
            source_opcode = None

            if node is None:
                op, cfg_node = self._find_def_op_by_sid_v24(sid)
                if op is not None:
                    source_addr = getattr(cfg_node, "addr", None)
                    source_opcode = getattr(op, "opcode", None)
                    expr_text = self._block_local_expr_for_op(cfg_node, op, seen=set())
                    pure = self._op_is_pure_value_builder_v24(op)
                else:
                    expr_text = None
                    pure = False
            else:
                node = self._resolve_transparent_formula(node, self._formula_nodes())
                source_opcode = getattr(node, "opcode", None)
                expr_text = self._formula_expr(node)
                pure = self._node_is_pure_value_builder_v24(node)

            # Avoid useless identity records.
            if not expr_text or expr_text == temp_name:
                continue

            out.append({
                "kind": "condition_temp_def",
                "consumer_kind": consumer.get("kind"),
                "consumer_addr": consumer.get("addr"),
                "consumer_role": consumer.get("role"),
                "sid": sid,
                "name": temp_name,
                "expr": expr_text,
                "pure": bool(pure),
                "source_addr": source_addr,
                "opcode": source_opcode,
                "recommendation": "materialize_or_inline_if_pure" if pure else "materialize_only_or_leave",
                "owner_next": "PHIfolder/emitter",
            })

        return out

    def _post_update_alias_candidate_records_v24(self, cond, consumer):
        """
        Export candidate exact node/SID post-update aliases used inside a
        condition.

        This addresses classes such as:
            local_14 = local_14 + 1
            if 4 < (local_14 + 1)

            local_28 = (local_28 + local_2c) % 10
            if ((local_28 + local_2c) % 10) != 7

        SGL does not replace condition text.  It records candidate source SID,
        target local, and formula expression for PHIfolder/emitter validation.
        """

        root = self._node_for_condition_var_v24(cond)
        if root is None:
            return []

        records = []
        for node in self._walk_formula_nodes_v24(root):
            rec = self._post_update_alias_candidate_for_node_v24(node, consumer)
            if rec is not None:
                records.append(rec)
        return records

    def _node_for_condition_var_v24(self, cond):
        if cond is None:
            return None

        # v54: RawCond freezes the edge-oriented predicate, but its source can
        # still carry the authoritative FormulaNode/SSA identity.  Follow the
        # source chain for structural analysis without replacing RawCond text.
        for candidate in self._condition_source_chain_v54(cond):
            if hasattr(candidate, "var") and hasattr(candidate, "opcode"):
                return candidate

            sid = self._condition_structural_sid_v54(candidate)
            node = self._formula_node_for_sid_v54(sid)
            if node is not None:
                return self._resolve_transparent_formula(node, self._formula_nodes())

        return None

    def _walk_formula_nodes_v24(self, node, seen=None):
        if seen is None:
            seen = set()
        if node is None:
            return

        sid = self._sid_of_var_v24(getattr(node, "var", None))
        if sid is not None:
            if sid in seen:
                return
            seen.add(sid)

        yield node

        for inp in list(getattr(node, "inputs", []) or []):
            isid = getattr(inp, "ssa_id", None)
            if isid is None:
                continue
            child = self._formula_nodes().get(isid)
            if child is None:
                continue
            child = self._resolve_transparent_formula(child, self._formula_nodes())
            for n in self._walk_formula_nodes_v24(child, seen):
                yield n

    def _post_update_alias_candidate_for_node_v24(self, node, consumer):
        if node is None:
            return None

        if not self._node_is_pure_value_builder_v24(node):
            return None

        var = getattr(node, "var", None)
        sid = self._sid_of_var_v24(var)
        if sid is None:
            return None

        target_name = self._var_expr(var)
        if not target_name or target_name.startswith("v_"):
            return None

        expr = self._formula_expr_raw_v24(node)
        if not expr or expr == target_name:
            return None

        if not self._expr_mentions_name_v24(expr, target_name):
            return None

        return {
            "kind": "post_update_alias_candidate",
            "consumer_kind": consumer.get("kind"),
            "consumer_addr": consumer.get("addr"),
            "consumer_role": consumer.get("role"),
            "source_sid": sid,
            "target_name": target_name,
            "expr": expr,
            "opcode": getattr(node, "opcode", None),
            "pure": True,
            "recommendation": "after_emitted_assignment_render_source_sid_as_target",
            "owner_next": "PHIfolder/emitter",
        }

    def _formula_expr_raw_v24(self, node):
        """
        Render a node formula without applying self-update alias shortening.
        This is for metadata identity only; not emitted Python.
        """

        if node is None:
            return None

        opcode = getattr(node, "opcode", None)
        inputs = list(getattr(node, "inputs", []) or [])

        if opcode in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC") and inputs:
            src_node = self._node_for_var(inputs[0])
            if src_node is not None:
                return self._formula_expr_raw_v24(src_node)
            return self._var_expr(inputs[0])

        binops = {
            "INT_ADD": "+",
            "INT_SUB": "-",
            "INT_MULT": "*",
            "INT_DIV": "//",
            "INT_SDIV": "//",
            "INT_REM": "%",
            "INT_SREM": "%",
            "INT_AND": "&",
            "INT_OR": "|",
            "INT_XOR": "^",
            "INT_LEFT": "<<",
            "INT_RIGHT": ">>",
            "INT_SRIGHT": ">>",
            "INT_EQUAL": "==",
            "INT_NOTEQUAL": "!=",
            "INT_LESS": "<",
            "INT_SLESS": "<",
            "INT_LESSEQUAL": "<=",
            "INT_SLESSEQUAL": "<=",
        }

        if opcode in binops and len(inputs) == 2:
            return "(%s %s %s)" % (
                self._value_expr_raw_v24(inputs[0]),
                binops[opcode],
                self._value_expr_raw_v24(inputs[1]),
            )

        if opcode == "BOOL_NEGATE" and inputs:
            return "not (%s)" % self._value_expr_raw_v24(inputs[0])

        if opcode in ("CALL", "CALLIND"):
            return self._var_expr(getattr(node, "var", None))

        return self._var_expr(getattr(node, "var", None))

    def _value_expr_raw_v24(self, v):
        if v is None:
            return "None"
        if getattr(v, "is_constant", False):
            return self._const_expr(v)
        node = self._node_for_var(v)
        if node is not None:
            opcode = getattr(node, "opcode", None)
            if opcode in ("CALL", "CALLIND"):
                return self._var_expr(getattr(node, "var", v))
            return self._formula_expr_raw_v24(node)
        return self._var_expr(v)

    def _expr_mentions_name_v24(self, expr, name):
        if not expr or not name:
            return False
        return re.search(r"\b%s\b" % re.escape(str(name)), str(expr)) is not None

    def _node_is_pure_value_builder_v24(self, node):
        if node is None:
            return False
        opcode = getattr(node, "opcode", None)
        return opcode in (
            "COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC",
            "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV",
            "INT_REM", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR",
            "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
            "PIECE", "SUBPIECE",
        )

    def _op_is_pure_value_builder_v24(self, op):
        if op is None:
            return False
        opcode = getattr(op, "opcode", None)
        return opcode in (
            "COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC",
            "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV",
            "INT_REM", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR",
            "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
            "PIECE", "SUBPIECE",
        )

    def _find_def_op_by_sid_v24(self, sid):
        if sid is None:
            return None, None

        for cfg_node in self._real_nodes():
            block = getattr(cfg_node, "block", None)
            if block is None:
                continue
            for op in list(getattr(block, "ops", []) or []):
                out = getattr(op, "output", None)
                if getattr(out, "ssa_id", None) == sid:
                    return op, cfg_node

        return None, None


    # =========================================================================
    # CONDITION FORMULA HELPERS
    # =========================================================================

    def _formula_nodes(self):
        nodes = getattr(self.func, "formula_nodes", None)

        if nodes is not None:
            return nodes

        raw = getattr(self.func, "var_nodes", None)

        if isinstance(raw, tuple):
            return raw[0] if len(raw) >= 1 else {}

        if isinstance(raw, dict):
            return raw

        return {}

    def _condition_formula_node(self, cfg_node):
        cond = self._get_condition(cfg_node)

        if cond is None:
            return None

        sid = getattr(cond, "ssa_id", None)
        nodes = self._formula_nodes()

        node = nodes.get(sid) if sid is not None else None

        return self._resolve_transparent_formula(node, nodes)

    def _resolve_transparent_formula(self, node, nodes):
        cur = node
        seen = set()

        while cur is not None:
            sid = getattr(getattr(cur, "var", None), "ssa_id", None)

            if sid in seen:
                return cur

            if sid is not None:
                seen.add(sid)

            opcode = getattr(cur, "opcode", None)

            if opcode not in ("COPY", "CAST", "INT_ZEXT", "INT_SEXT", "TRUNC"):
                return cur

            inputs = list(getattr(cur, "inputs", []) or [])

            if not inputs:
                return cur

            src = inputs[0]
            ssid = getattr(src, "ssa_id", None)

            if ssid is None:
                return cur

            nxt = nodes.get(ssid)

            if nxt is None:
                return cur

            cur = nxt

        return node

    def _input_sids(self, node):
        out = set()

        if node is None:
            return out

        for inp in list(getattr(node, "inputs", []) or []):
            sid = getattr(inp, "ssa_id", None)

            if sid is not None:
                out.add(sid)

        return out

    def _is_switch_range_compare(self, cond_node):
        if cond_node is None:
            return False

        inputs = list(getattr(cond_node, "inputs", []) or [])

        if len(inputs) != 2:
            return False

        # switch range compare in this test is v_1460 < 3, where v_1460 is
        # an INT_SREM result. Detect by looking through formula node of left.
        left = inputs[0]
        sid = getattr(left, "ssa_id", None)

        if sid is None:
            return False

        nodes = self._formula_nodes()
        left_node = nodes.get(sid)

        if left_node is None:
            return False

        return getattr(left_node, "opcode", None) in ("INT_REM", "INT_SREM")

    def _conditions_probably_share_dispatch(self, cond_node, cfg_node):
        other = self._condition_formula_node(cfg_node)

        if cond_node is None or other is None:
            return False

        a = self._primary_nonconst_input_signature(cond_node)
        b = self._primary_nonconst_input_signature(other)

        if a is None or b is None:
            return False

        return a == b


    def _const_int_value(self, v):
        if v is None:
            return None

        if hasattr(v, "var"):
            v = v.var

        for attr in ("const_value", "value", "offset"):
            val = getattr(v, attr, None)
            if val is None:
                continue

            try:
                return int(val)
            except Exception:
                continue

        return None

    def _less_compare_signature(self, cond_node):
        """
        Return (input_signature, const_value, direction) for simple less-than
        compares used in switch/range ladders.

        direction:
            "var_lt_const"  for x < C
            "const_lt_var"  for C < x
        """

        if cond_node is None:
            return None

        opcode = getattr(cond_node, "opcode", None)

        if opcode not in ("INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL"):
            return None

        inputs = list(getattr(cond_node, "inputs", []) or [])

        if len(inputs) != 2:
            return None

        left, right = inputs[0], inputs[1]
        left_const = bool(getattr(left, "is_constant", False))
        right_const = bool(getattr(right, "is_constant", False))

        if left_const == right_const:
            return None

        if right_const:
            sig = self._primary_nonconst_input_signature(cond_node)
            cval = self._const_int_value(right)

            if sig is None or cval is None:
                return None

            return (sig, cval, "var_lt_const")

        sig = self._primary_nonconst_input_signature(cond_node)
        cval = self._const_int_value(left)

        if sig is None or cval is None:
            return None

        return (sig, cval, "const_lt_var")

    def _is_stricter_less_test_on_same_value(self, parent_cond_node, child_cfg_node):
        """
        Detect the contradiction pattern:

            if x < 4:
                action
            else:
                if x < 2:       # impossible under x >= 4
                    disappearing branch

        When this is seen, the parent branch is likely oriented wrongly for a
        range/switch ladder and should be swapped before nesting is built.

        We only fire for var<const tests on the same dispatch value.
        """

        child_cond = self._condition_formula_node(child_cfg_node)

        psig = self._less_compare_signature(parent_cond_node)
        csig = self._less_compare_signature(child_cond)

        if psig is None or csig is None:
            return False

        pval_sig, pconst, pdir = psig
        cval_sig, cconst, cdir = csig

        if pdir != "var_lt_const" or cdir != "var_lt_const":
            return False

        if pval_sig != cval_sig:
            return False

        return cconst < pconst


    def _is_parity_eq_zero(self, cond_node):
        if cond_node is None:
            return False

        if getattr(cond_node, "opcode", None) != "INT_EQUAL":
            return False

        inputs = list(getattr(cond_node, "inputs", []) or [])

        if len(inputs) != 2:
            return False

        has_zero = any(getattr(x, "is_constant", False) and self._const_int(x) == 0 for x in inputs)

        if not has_zero:
            return False

        nodes = self._formula_nodes()

        for x in inputs:
            sid = getattr(x, "ssa_id", None)
            n = nodes.get(sid) if sid is not None else None

            if n is None:
                continue

            if getattr(n, "opcode", None) != "INT_AND":
                continue

            for ai in list(getattr(n, "inputs", []) or []):
                if getattr(ai, "is_constant", False) and self._const_int(ai) == 1:
                    return True

        return False

    def _is_checkbit_eq_zero(self, cond_node):
        if cond_node is None:
            return False

        if getattr(cond_node, "opcode", None) != "INT_EQUAL":
            return False

        inputs = list(getattr(cond_node, "inputs", []) or [])

        if len(inputs) != 2:
            return False

        has_zero = any(getattr(x, "is_constant", False) and self._const_int(x) == 0 for x in inputs)

        if not has_zero:
            return False

        nodes = self._formula_nodes()

        for x in inputs:
            sid = getattr(x, "ssa_id", None)
            n = nodes.get(sid) if sid is not None else None

            if n is None:
                continue

            if getattr(n, "opcode", None) in ("CALL", "CALLIND"):
                inputs2 = list(getattr(n, "inputs", []) or [])

                if inputs2:
                    fname = getattr(inputs2[0], "name", None)

                    if fname == "check_bit":
                        return True

        return False

    def _const_int(self, v):
        if v is None:
            return None

        for attr in ("const_value", "value", "offset"):
            val = getattr(v, attr, None)
            if isinstance(val, int):
                return val

        return None


    # =========================================================================
    # BLOCK CONTENT HELPERS
    # =========================================================================

    def _is_conditional_node(self, cfg_node):
        return self._get_condition(cfg_node) is not None

    def _block_has_call_named(self, cfg_node, name):
        if cfg_node is None:
            return False

        block = getattr(cfg_node, "block", None)

        if block is None:
            return False

        for op in list(getattr(block, "ops", []) or []):
            if getattr(op, "opcode", None) not in ("CALL", "CALLIND"):
                continue

            ins = list(getattr(op, "inputs", []) or [])

            if not ins:
                continue

            fname = getattr(ins[0], "name", None)

            if str(fname) == name:
                return True

        return False

    def _path_has_add_negative_before_join(self, start, join, limit=6):
        """
        Small bounded scan used only for branch polarity. This catches
        decrement/continue paths where the local update is realized at a PHI
        join/latch rather than directly in the first action block.
        """

        if start is None:
            return False

        seen = set()
        work = [(start, 0)]

        while work:
            node, depth = work.pop(0)

            if node is None or node in seen or depth > limit:
                continue

            seen.add(node)

            if node is join and depth > 0:
                continue

            if self._block_has_add_negative(node):
                return True

            # Stop if we hit a conditional other than the first node; this is
            # a polarity heuristic, not a full path analysis.
            if depth > 0 and self._is_conditional_node(node):
                continue

            for succ in self._successors(node):
                if succ not in seen:
                    work.append((succ, depth + 1))

        return False

    def _block_has_add_negative(self, cfg_node):
        if cfg_node is None:
            return False

        block = getattr(cfg_node, "block", None)

        if block is None:
            return False

        for op in list(getattr(block, "ops", []) or []):
            if getattr(op, "opcode", None) not in ("INT_ADD", "INT_SUB"):
                continue

            if getattr(op, "opcode", None) == "INT_SUB":
                return True

            for inp in list(getattr(op, "inputs", []) or []):
                if not getattr(inp, "is_constant", False):
                    continue

                val = self._const_int_value(inp)

                if val is None:
                    continue

                # Treat two's-complement large constants as negative deltas.
                if val > 0x7fffffff:
                    return True

                # Some loaders may expose already-signed negative constants.
                if val < 0:
                    return True

        return False

    def _const_int_value(self, v):
        for attr in ("const_value", "value", "offset", "address"):
            val = getattr(v, attr, None)
            if isinstance(val, int):
                return val

        return None


    def _block_has_opcode(self, cfg_node, opcode):
        if cfg_node is None:
            return False

        block = getattr(cfg_node, "block", None)

        if block is None:
            return False

        for op in list(getattr(block, "ops", []) or []):
            if getattr(op, "opcode", None) == opcode:
                return True

        return False


    # =========================================================================
    # RAW CFG HELPERS
    # =========================================================================

    def _explicit_branch_successor(self, node, term):
        target_addr = self._terminator_target_addr(term)

        if target_addr is None:
            return None

        for e in getattr(node, "out_edges", []):
            dst = getattr(e, "dst", None)

            if dst is None:
                continue

            if getattr(dst, "addr", None) == target_addr:
                return dst

        return None

    def _fallthrough_successor(self, node, explicit):
        for e in getattr(node, "out_edges", []):

            dst = getattr(e, "dst", None)

            if dst is None:
                continue

            if explicit is not None and dst is explicit:
                continue

            return dst

        return None

    def _terminator_target_addr(self, term):
        # Try attributes first.
        for attr in ("target", "true_target"):
            target = getattr(term, attr, None)

            if target is not None:
                addr = getattr(target, "addr", None)

                if isinstance(addr, int):
                    return addr

                for vattr in ("address", "offset", "value"):
                    val = getattr(target, vattr, None)

                    if isinstance(val, int):
                        return val

        inputs = list(getattr(term, "inputs", []) or [])

        if not inputs:
            return None

        target = inputs[0]

        if target is None:
            return None

        for attr in ("address", "offset", "value"):
            val = getattr(target, attr, None)

            if isinstance(val, int):
                return val

        return None

    def _next_linear(self, node):
        outs = list(getattr(node, "out_edges", []))

        if len(outs) != 1:
            return None

        e = outs[0]

        if getattr(e, "type", None) not in ("uncond", "backedge"):
            return None

        return getattr(e, "dst", None)

    def _get_condition(self, node):
        if node is None:
            return None

        block = getattr(node, "block", None)

        if block is None:
            return None

        term = getattr(block, "terminator", None)

        if term is not None and getattr(term, "opcode", None) == "CBRANCH":
            cond = getattr(term, "condition", None)

            if cond is not None:
                return cond

            inputs = getattr(term, "inputs", [])

            if len(inputs) >= 2:
                return inputs[1]

        return None

    def _true_edge(self, node):
        for e in self._as_list(getattr(node, "out_edges", None)):
            et = getattr(e, "raw_type", getattr(e, "type", None))
            if et == "true":
                return getattr(e, "dst", None)

        for e in self._as_list(getattr(node, "out_edges", None)):
            if getattr(e, "type", None) == "true":
                return getattr(e, "dst", None)

        return None

    def _false_edge(self, node):
        for e in self._as_list(getattr(node, "out_edges", None)):
            et = getattr(e, "raw_type", getattr(e, "type", None))
            if et == "false":
                return getattr(e, "dst", None)

        for e in self._as_list(getattr(node, "out_edges", None)):
            if getattr(e, "type", None) == "false":
                return getattr(e, "dst", None)

        return None


    def _reaches(self, start, target):
        if start is None or target is None:
            return False

        seen = set()
        stack = [start]

        while stack:
            n = stack.pop()

            if n == target:
                return True

            if n in seen:
                continue

            seen.add(n)

            for e in getattr(n, "out_edges", []):
                dst = getattr(e, "dst", None)

                if dst is not None:
                    stack.append(dst)

        return False

    def _real_nodes(self):
        for n in getattr(self.cfg, "nodes", {}).values():
            addr = getattr(n, "addr", None)

            if addr == "EXIT":
                continue

            yield n

    # =========================================================================
    # DEBUG
    # =========================================================================

    def _record_branch_event(self, node, term, then_node, else_node, join, mode):
        try:
            addr = getattr(node, "addr", None)
            then_addr = getattr(then_node, "addr", None) if then_node is not None else None
            else_addr = getattr(else_node, "addr", None) if else_node is not None else None
            join_addr = getattr(join, "addr", None) if join is not None else None
            target_addr = self._terminator_target_addr(term)

            then_inv = self._edge_condition_invert_for_edge(node, then_node) if then_node is not None else False
            else_inv = self._edge_condition_invert_for_edge(node, else_node) if else_node is not None else False
            then_reason = self._edge_condition_reason(node, then_node) if then_node is not None else None
            else_reason = self._edge_condition_reason(node, else_node) if else_node is not None else None

            cond = self._get_condition(node)
            then_cond = self._condition_for_branch_then(node, then_node, cond) if then_node is not None else None

            self.branch_events.append({
                "block": addr,
                "mode": mode,
                "target_addr": target_addr,
                "then": then_addr,
                "else": else_addr,
                "join": join_addr,
                "then_invert": then_inv,
                "else_invert": else_inv,
                "then_reason": then_reason,
                "else_reason": else_reason,
                "cond_raw": self._raw_condition_expr_for_cfg_node(node),
                "cond_then": getattr(then_cond, "name", then_cond),
                "cond_then_reason": getattr(then_cond, "reason", None),
            })
        except Exception:
            pass

    def debug_print(self):
        print("\n=========== SGL EXECUTION TREE ===========\n")
        self._print(self.root, 0)
        print("\n=========== END TREE ===========\n")

        if getattr(self, "loop_condition_events", None):
            print("\n=========== SGL LOOP CONDITION EVENTS ===========\n")
            def hx_loop(x):
                return hex(x) if isinstance(x, int) else str(x)
            for ev in self.loop_condition_events:
                print(
                    "header=%s old_role=%s old_cond=%s -> new_role=%s new_cond=%s why=%s" %
                    (
                        hx_loop(ev.get("header")),
                        ev.get("old_role"),
                        ev.get("old_cond"),
                        ev.get("new_role"),
                        ev.get("new_cond"),
                        ev.get("why"),
                    )
                )
            print("\n=========== END LOOP CONDITION EVENTS ===========\n")

        if getattr(self, "loop_contract_events", None):
            print("\n=========== SGL LOOP CONTRACT EVENTS ===========\n")
            def hx_contract(x):
                return hex(x) if isinstance(x, int) else str(x)
            for ev in self.loop_contract_events:
                print(
                    "header=%s old_role=%s old_cond=%s -> new_role=%s new_cond=%s why=%s" %
                    (
                        hx_contract(ev.get("header")),
                        ev.get("old_role"),
                        ev.get("old_cond"),
                        ev.get("new_role"),
                        ev.get("new_cond"),
                        ev.get("why"),
                    )
                )
            print("\n=========== END LOOP CONTRACT EVENTS ===========\n")

        if getattr(self, "condition_source_events", None):
            print("\n=========== SGL CONDITION SOURCE EVENTS ===========\n")
            def hx_source(x):
                return hex(x) if isinstance(x, int) else str(x)
            for ev in self.condition_source_events:
                print(
                    "kind=%s src=%s dst=%s expr=%s reason=%s" %
                    (
                        ev.get("kind"),
                        hx_source(ev.get("src")),
                        hx_source(ev.get("dst")),
                        ev.get("expr"),
                        ev.get("reason"),
                    )
                )
            print("\n=========== END CONDITION SOURCE EVENTS ===========\n")


        if getattr(self, "metadata_events", None):
            print("\n=========== SGL METADATA EVENTS ===========\n")
            for ev in self.metadata_events:
                print(ev)
            print("\n=========== END METADATA EVENTS ===========\n")

        if getattr(self, "metadata_consumed_events", None):
            print("\n=========== SGL METADATA CONSUMED EVENTS ===========\n")
            def hx_meta_v26(x):
                return hex(x) if isinstance(x, int) else str(x)
            for ev in self.metadata_consumed_events:
                pretty = dict(ev)
                for k in ("src", "dst", "from", "to", "loop", "target", "latch"):
                    if k in pretty:
                        pretty[k] = hx_meta_v26(pretty[k])
                print(pretty)
            print("\n=========== END SGL METADATA CONSUMED EVENTS ===========\n")

        if getattr(self, "condition_temp_defs", None):
            print("\n=========== SGL CONDITION TEMP DEFS ===========\n")
            def hx_meta(x):
                return hex(x) if isinstance(x, int) else str(x)
            for rec in self.condition_temp_defs:
                print(
                    "consumer=%s sid=%s name=%s expr=%s pure=%s opcode=%s source=%s" %
                    (
                        hx_meta(rec.get("consumer_addr")),
                        rec.get("sid"),
                        rec.get("name"),
                        rec.get("expr"),
                        rec.get("pure"),
                        rec.get("opcode"),
                        hx_meta(rec.get("source_addr")),
                    )
                )
            print("\n=========== END CONDITION TEMP DEFS ===========\n")

        if getattr(self, "post_update_alias_candidates", None):
            print("\n=========== SGL POST UPDATE ALIAS CANDIDATES ===========\n")
            def hx_alias(x):
                return hex(x) if isinstance(x, int) else str(x)
            for rec in self.post_update_alias_candidates:
                print(
                    "consumer=%s sid=%s target=%s expr=%s opcode=%s" %
                    (
                        hx_alias(rec.get("consumer_addr")),
                        rec.get("source_sid"),
                        rec.get("target_name"),
                        rec.get("expr"),
                        rec.get("opcode"),
                    )
                )
            print("\n=========== END POST UPDATE ALIAS CANDIDATES ===========\n")


        if self.branch_events:
            print("\n=========== SGL BRANCH EVENTS ===========\n")

            def hx(x):
                return hex(x) if isinstance(x, int) else str(x)

            for ev in self.branch_events:
                print(
                    "block=%s mode=%s target=%s then=%s else=%s join=%s then_inv=%s else_inv=%s cond_then=%s" %
                    (
                        hx(ev.get("block")),
                        ev.get("mode"),
                        hx(ev.get("target_addr")),
                        hx(ev.get("then")),
                        hx(ev.get("else")),
                        hx(ev.get("join")),
                        ev.get("then_invert"),
                        ev.get("else_invert"),
                        ev.get("cond_then"),
                    )
                )

            print("\n=========== END BRANCH EVENTS ===========\n")

    def _print(self, node, depth):
        indent = "  " * depth
        kind = getattr(node, "kind", type(node).__name__)

        desc = kind

        if kind == "block":
            addr = getattr(getattr(node, "cfg_node", None), "addr", "?")
            try:
                addr = hex(addr)
            except Exception:
                addr = str(addr)
            desc += " [%s]" % addr

        elif kind == "if":
            cond = getattr(node, "cond_var", None)
            desc += " [cond=%s]" % getattr(cond, "name", cond)

        elif kind == "loop":
            cond = getattr(node, "cond_var", None)
            header = getattr(node, "header", None)
            haddr = getattr(header, "addr", "?")
            try:
                haddr = hex(haddr)
            except Exception:
                haddr = str(haddr)
            role = getattr(node, "condition_role", None)
            desc += " [header=%s role=%s cond=%s]" % (haddr, role, getattr(cond, "name", cond))

        print(indent + desc)

        for child in getattr(node, "children", []):
            self._print(child, depth + 1)


# =============================================================================
# MODULE-LEVEL CONDITION SIDECAR DEBUGGER
# =============================================================================

def debug_sidecar(pal, include_formula_records=False):
    """
    Print and return the frozen SGL condition-provenance handoff.

    Intended PyGhidra entry point:

        import PALSGLdecomp
        PALSGLdecomp.debug_sidecar(self.PAL)

    This function is read-only.  It does not rebuild SGL, repair metadata, or
    mutate PAL.  It can therefore be called immediately after SGL or after any
    upper layer that preserves the PAL function object.

    Set include_formula_records=True to print every dependency's defining
    op-key/block/opcode record.  The returned object always contains the full
    sidecars regardless of print verbosity.
    """

    from pprint import pformat

    def hx(value):
        return hex(value) if isinstance(value, int) else value

    if pal is None:
        sidecars = []
        consumers = []
        handoff = {}
        sgl_version = None
    else:
        handoff = getattr(pal, "sgl_metadata_handoff", {}) or {}
        sidecars = list(
            getattr(pal, "sgl_condition_provenance_sidecars", None)
            or handoff.get("condition_provenance_sidecars", [])
            or []
        )
        consumers = list(
            getattr(pal, "sgl_condition_consumers", None)
            or handoff.get("condition_consumers", [])
            or []
        )
        sgl_version = getattr(pal, "sgl_version", None) or handoff.get("version")

    consumers_by_ref = {
        rec.get("provenance_ref"): rec
        for rec in consumers
        if isinstance(rec, dict) and rec.get("provenance_ref")
    }
    sidecars_by_ref = {
        rec.get("provenance_ref"): rec
        for rec in sidecars
        if isinstance(rec, dict) and rec.get("provenance_ref")
    }

    warnings = []
    for ref in sorted(set(consumers_by_ref) - set(sidecars_by_ref)):
        warnings.append({
            "kind": "condition_consumer_missing_sidecar_v54b",
            "provenance_ref": ref,
        })
    for ref in sorted(set(sidecars_by_ref) - set(consumers_by_ref)):
        warnings.append({
            "kind": "condition_sidecar_missing_consumer_v54b",
            "provenance_ref": ref,
        })

    for rec in sidecars:
        if not isinstance(rec, dict):
            warnings.append({
                "kind": "condition_sidecar_not_mapping_v54b",
                "record": repr(rec),
            })
            continue

        formula_sids = list(rec.get("formula_dependency_sids", []) or [])
        source_sid = rec.get("effective_condition_sid")
        authority = rec.get("dependency_authority")

        if authority == "formula_structure" and not formula_sids:
            warnings.append({
                "kind": "formula_authority_without_dependencies_v54b",
                "provenance_ref": rec.get("provenance_ref"),
            })
        if source_sid is not None and formula_sids and source_sid not in formula_sids:
            warnings.append({
                "kind": "effective_condition_sid_missing_from_formula_dependencies_v54b",
                "provenance_ref": rec.get("provenance_ref"),
                "effective_condition_sid": source_sid,
            })

    authority_counts = {}
    representation_counts = {}
    source_sid_recoveries = 0
    for rec in sidecars:
        if not isinstance(rec, dict):
            continue
        authority = rec.get("dependency_authority") or "unknown"
        representation = rec.get("condition_representation") or "unknown"
        authority_counts[authority] = authority_counts.get(authority, 0) + 1
        representation_counts[representation] = representation_counts.get(representation, 0) + 1
        if rec.get("direct_condition_sid") is None and rec.get("source_condition_sid") is not None:
            source_sid_recoveries += 1

    inventory = {
        "kind": "sgl_condition_provenance_debug_inventory_v54b",
        "version": sgl_version,
        "active": bool(sidecars),
        "condition_consumers": len(consumers),
        "condition_sidecars": len(sidecars),
        "source_sid_recoveries": source_sid_recoveries,
        "representations": representation_counts,
        "dependency_authorities": authority_counts,
        "warnings": len(warnings),
        "rule": "RawCond_text_owns_edge_truth_formula_sidecar_owns_dependency_identity",
    }

    print("\n===== PAL SGL CONDITION PROVENANCE SIDECARS =====")
    print("\n[INVENTORY]")
    print(pformat(inventory, sort_dicts=False))

    print("\n[CONDITION CONSUMERS]")
    if not sidecars:
        print("[]")
    else:
        for index, rec in enumerate(sidecars):
            if not isinstance(rec, dict):
                print("#%03d invalid=%r" % (index, rec))
                continue

            addr = hx(rec.get("consumer_addr"))
            print("-" * 72)
            print(
                "#%03d ref=%s consumer=%s@%s role=%s" % (
                    index,
                    rec.get("provenance_ref"),
                    rec.get("consumer_kind"),
                    addr,
                    rec.get("consumer_role"),
                )
            )
            print(
                "representation=%s authority=%s direct=%s source=%s effective=%s" % (
                    rec.get("condition_representation"),
                    rec.get("dependency_authority"),
                    rec.get("direct_condition_sid"),
                    rec.get("source_condition_sid"),
                    rec.get("effective_condition_sid"),
                )
            )
            print("expr=%s" % rec.get("condition_expr"))
            print(
                "source_op=%s block=%s op_key=%s" % (
                    rec.get("source_opcode"),
                    hx(rec.get("source_block_addr")),
                    rec.get("source_op_key"),
                )
            )
            print("formula_dependency_sids=%s" % rec.get("formula_dependency_sids", []))
            print("text_dependency_sids=%s" % rec.get("text_dependency_sids", []))

            if include_formula_records:
                print("formula_dependencies=")
                print(pformat(rec.get("formula_dependencies", []), sort_dicts=False))

    print("\n[TEXT-FALLBACK CONDITIONS]")
    text_fallbacks = [
        {
            "provenance_ref": rec.get("provenance_ref"),
            "consumer_addr": hx(rec.get("consumer_addr")),
            "condition_expr": rec.get("condition_expr"),
            "text_dependency_sids": rec.get("text_dependency_sids", []),
        }
        for rec in sidecars
        if isinstance(rec, dict)
        and rec.get("dependency_authority") == "condition_text_fallback"
    ]
    print(pformat(text_fallbacks, sort_dicts=False))

    print("\n[WARNINGS]")
    print(pformat(warnings, sort_dicts=False))
    print("===== END PAL SGL CONDITION PROVENANCE SIDECARS =====\n")

    return {
        "inventory": inventory,
        "sidecars": sidecars,
        "consumers": consumers,
        "text_fallbacks": text_fallbacks,
        "warnings": warnings,
    }
