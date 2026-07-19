# ============================================================
# PALRawAudit.py
# PALRAW v0.3
#
# Raw instruction p-code truth audit versus Ghidra HighFunction
# p-code / PAL CFG.
#
# v0.1 problem:
#   It compared the first instruction at a HighFunction block start
#   against the whole HF/PAL block successor set. For blocks that begin
#   with MOV/CMP and branch later, this creates false "successors_differ"
#   findings.
#
# v0.2 fix:
#   Audit the raw instruction SPAN belonging to the PAL/HF block.
#   The comparison uses the terminal raw control-flow instruction's
#   flow targets + fallthrough, not the first instruction's fallthrough.
#
# v0.3 fix:
#   CALL is not treated as a terminal CFG edge when it has fallthrough.
#   Non-block-start fallthrough stubs are linearly resolved to HF targets.
#
# ============================================================


class PALRawAudit:

    DEFAULT_MAX_SCAN_INSNS = 64

    def __init__(self,
                 pal_function=None,
                 program=None,
                 decompiler_interface=None,
                 monitor=None):

        self.pal = pal_function
        self.program = program
        self.decompiler_interface = decompiler_interface
        self.monitor = monitor

        self.report = []
        self.errors = []

        self._addr_factory = None
        self._listing = None
        self._cfg_nodes = {}
        self._pal_blocks_by_addr = {}

        self._init_indexes()

    # ---------------------------------------------------------
    # INIT / COMPAT
    # ---------------------------------------------------------

    def _init_indexes(self):

        if self.program is not None:
            try:
                self._addr_factory = self.program.getAddressFactory()
            except Exception:
                self._addr_factory = None

            try:
                self._listing = self.program.getListing()
            except Exception:
                self._listing = None

        if self.pal is not None:
            cfg = getattr(self.pal, "cfg", None)
            nodes = getattr(cfg, "nodes", None)
            self._cfg_nodes = nodes if isinstance(nodes, dict) else {}

            for b in self._as_list(getattr(self.pal, "blocks", None)):
                addr = getattr(b, "addr", None)
                if addr is not None:
                    self._pal_blocks_by_addr[int(addr)] = b

    def _as_list(self, maybe_iterable):
        if maybe_iterable is None:
            return []

        try:
            if callable(maybe_iterable):
                maybe_iterable = maybe_iterable()
        except Exception:
            return []

        if maybe_iterable is None:
            return []

        try:
            return list(maybe_iterable)
        except TypeError:
            return [maybe_iterable]
        except Exception:
            return []

    # ---------------------------------------------------------
    # ADDRESS HELPERS
    # ---------------------------------------------------------

    def to_addr(self, x):

        if x is None:
            return None

        if hasattr(x, "getOffset"):
            return x

        try:
            x = int(x)
        except Exception:
            return None

        if self._addr_factory is None:
            return None

        try:
            space = self._addr_factory.getDefaultAddressSpace()
            return space.getAddress(x)
        except Exception:
            return None

    def addr_int(self, addr):

        if addr is None:
            return None

        if isinstance(addr, int):
            return addr

        try:
            return int(addr.getOffset())
        except Exception:
            return None

    def fmt_addr(self, x):

        if x is None:
            return None

        i = self.addr_int(x)
        if i is None:
            return str(x)

        return "0x%x" % i

    def parse_addr(self, x):
        try:
            if isinstance(x, str) and x.startswith("0x"):
                return int(x, 16)
            return int(x)
        except Exception:
            return None

    # ---------------------------------------------------------
    # PAL/HF BLOCK HELPERS
    # ---------------------------------------------------------

    def find_pal_block(self, addr_int):
        """
        Prefer exact PAL block start, otherwise nearest containing/preceding
        block. This supports internal targets such as 0x101252.
        """
        if addr_int is None:
            return None

        addr_int = int(addr_int)

        block = self._pal_blocks_by_addr.get(addr_int)
        if block is not None:
            return block

        starts = sorted(self._pal_blocks_by_addr.keys())
        prev = None
        for s in starts:
            if s <= addr_int:
                prev = s
            else:
                break

        if prev is None:
            return None

        return self._pal_blocks_by_addr.get(prev)

    def block_start(self, block):
        if block is None:
            return None
        a = getattr(block, "addr", None)
        return int(a) if a is not None else None

    def block_successor_addrs(self, block):
        out = []

        cfg_node = None
        if block is not None and self._cfg_nodes:
            cfg_node = self._cfg_nodes.get(getattr(block, "addr", None))

        if cfg_node is None and block is not None:
            cfg_node = getattr(block, "cfg_node", None)

        if cfg_node is None:
            return out

        # Prefer explicit edge records.
        for e in self._as_list(getattr(cfg_node, "out_edges", None)):
            dst = getattr(e, "dst", None)
            da = getattr(dst, "addr", None)
            if da is not None:
                if da != "EXIT":
                    out.append(int(da))

        if out:
            return sorted(set(out))

        # Fallback to successor nodes.
        for s in self._as_list(getattr(cfg_node, "successors", None)):
            sa = getattr(s, "addr", None)
            if sa is not None:
                if sa != "EXIT":
                    out.append(int(sa))

        return sorted(set(out))

    def next_pal_block_start_after(self, addr_int):
        starts = sorted(self._pal_blocks_by_addr.keys())
        for s in starts:
            if s > addr_int:
                return s
        return None

    # ---------------------------------------------------------
    # RAW INSTRUCTION EXTRACTION
    # ---------------------------------------------------------

    def get_instruction(self, addr_int):

        if self._listing is None:
            return None

        addr = self.to_addr(addr_int)

        if addr is None:
            return None

        try:
            return self._listing.getInstructionAt(addr)
        except Exception:
            return None

    def get_instruction_containing(self, addr_int):
        """
        Useful when an HF target points inside a machine instruction.
        """
        if self._listing is None:
            return None

        addr = self.to_addr(addr_int)
        if addr is None:
            return None

        try:
            return self._listing.getInstructionContaining(addr)
        except Exception:
            return None

    def raw_instruction_record(self, addr_int):

        rec = {
            "addr": self.fmt_addr(addr_int),
            "instruction_found": False,
            "assembly": None,
            "mnemonic": None,
            "fallthrough": None,
            "flows": [],
            "raw_pcode": [],
            "raw_pcode_error": None,
        }

        instr = self.get_instruction(addr_int)

        if instr is None:
            instr = self.get_instruction_containing(addr_int)

        if instr is None:
            rec["raw_pcode_error"] = "no instruction at/containing address"
            return rec

        rec["instruction_found"] = True

        try:
            rec["addr"] = self.fmt_addr(instr.getAddress())
        except Exception:
            pass

        try:
            rec["assembly"] = str(instr)
        except Exception:
            rec["assembly"] = None

        try:
            rec["mnemonic"] = str(instr.getMnemonicString())
        except Exception:
            rec["mnemonic"] = None

        try:
            ft = instr.getFallThrough()
            rec["fallthrough"] = self.fmt_addr(ft)
        except Exception:
            rec["fallthrough"] = None

        try:
            flows = instr.getFlows()
            rec["flows"] = [self.fmt_addr(f) for f in flows]
        except Exception:
            rec["flows"] = []

        try:
            pcode_ops = instr.getPcode()
            rec["raw_pcode"] = [self.format_raw_pcode_op(op) for op in pcode_ops]
        except Exception as e:
            rec["raw_pcode_error"] = repr(e)

        return rec


    def _mnemonic_upper(self, irec):
        m = irec.get("mnemonic")
        if not m:
            asm = irec.get("assembly") or ""
            m = asm.split()[0] if asm.split() else ""
        return str(m).upper()

    def _is_call_instruction_record(self, irec):
        m = self._mnemonic_upper(irec)
        return m.startswith("CALL")

    def _is_unconditional_jump_instruction_record(self, irec):
        m = self._mnemonic_upper(irec)
        return m in ("JMP", "BR", "BRA")

    def _is_conditional_jump_instruction_record(self, irec):
        m = self._mnemonic_upper(irec)
        if not m.startswith("J"):
            return False
        return not self._is_unconditional_jump_instruction_record(irec)

    def _is_terminal_control_instruction_record(self, irec):
        """
        True for actual block-terminating control flow.

        CALL has an explicit flow target but returns to fallthrough, so it is
        not a terminal CFG branch for this audit unless there is no fallthrough.
        """
        if not irec:
            return False

        if self._is_call_instruction_record(irec):
            return irec.get("fallthrough") is None

        if self._is_unconditional_jump_instruction_record(irec):
            return True

        if self._is_conditional_jump_instruction_record(irec):
            return True

        if irec.get("fallthrough") is None:
            return True

        return False

    def _resolve_raw_successor_to_hf_target(self, succ_addr, current_block=None, depth=0):
        """
        Normalize a raw successor address to a PAL/HF CFG target.

        Raw fallthroughs often land in short compiler stubs that are not
        HighFunction block starts, e.g. a fallthrough landing at 0x101226
        followed by a short JMP to 0x101255.  Resolve such linear tails so
        PALRAW compares semantic CFG successors rather than instruction-local
        addresses.

        This is intentionally conservative.
        """
        if succ_addr is None or depth > 8:
            return succ_addr

        si = self.parse_addr(succ_addr)
        if si is None:
            return succ_addr

        # Exact PAL block start.
        if si in self._pal_blocks_by_addr:
            return self.fmt_addr(si)

        # If this address is one of the known CFG successor starts after
        # normalization through containing block, keep that start.
        block = self.find_pal_block(si)
        if block is not None:
            bstart = self.block_start(block)

            # If successor is exactly inside a different containing block,
            # normalize to that block start.  Avoid mapping fallthrough stubs
            # back to the current block; those need linear resolution.
            if current_block is not None and bstart == self.block_start(current_block):
                pass
            elif bstart is not None:
                return self.fmt_addr(bstart)

        instr = self.get_instruction(si)
        if instr is None:
            instr = self.get_instruction_containing(si)
        if instr is None:
            return self.fmt_addr(si)

        irec = self.raw_instruction_record(self.addr_int(instr.getAddress()))

        # Follow unconditional trampoline.
        if self._is_unconditional_jump_instruction_record(irec):
            flows = irec.get("flows") or []
            if flows:
                return self._resolve_raw_successor_to_hf_target(
                    flows[0],
                    current_block=current_block,
                    depth=depth + 1,
                )

        # For short non-branch stubs, walk fallthrough until a PAL block start
        # or an unconditional jump.  Stop at conditional branches.
        if self._is_conditional_jump_instruction_record(irec):
            return self.fmt_addr(si)

        ft = irec.get("fallthrough")
        if ft is None:
            return self.fmt_addr(si)

        fti = self.parse_addr(ft)
        if fti is None:
            return self.fmt_addr(si)

        if fti in self._pal_blocks_by_addr:
            return self.fmt_addr(fti)

        return self._resolve_raw_successor_to_hf_target(
            ft,
            current_block=current_block,
            depth=depth + 1,
        )


    def raw_block_record(self, requested_addr, hf_block=None):
        """
        Scan raw instructions from HF/PAL block start until the raw terminal
        control-flow instruction or until the next PAL block boundary.

        The comparison must be made against this terminal raw instruction,
        not the first instruction in the block.
        """
        block_start = self.block_start(hf_block)
        start = block_start if block_start is not None else int(requested_addr)

        successor_addrs = self.block_successor_addrs(hf_block) if hf_block is not None else []
        next_block = self.next_pal_block_start_after(start)

        rec = {
            "requested_addr": self.fmt_addr(requested_addr),
            "block_start": self.fmt_addr(start),
            "next_block_start": self.fmt_addr(next_block),
            "hf_successors_hint": [self.fmt_addr(x) for x in successor_addrs],
            "instructions": [],
            "terminal_instruction": None,
            "terminal_successors": [],
            "scan_notes": [],
        }

        cur = int(start)
        seen = set()

        for _ in range(self.DEFAULT_MAX_SCAN_INSNS):
            if cur in seen:
                rec["scan_notes"].append("scan loop detected at %s" % self.fmt_addr(cur))
                break
            seen.add(cur)

            instr = self.get_instruction(cur)
            if instr is None:
                rec["scan_notes"].append("no instruction at %s" % self.fmt_addr(cur))
                break

            irec = self.raw_instruction_record(cur)
            rec["instructions"].append(irec)

            succs = self.raw_successors_from_instruction_record(irec)

            # v0.3: CALL has a flow target but is normally not a terminal CFG
            # branch because execution returns to fallthrough.  Only real
            # terminal control instructions end the raw block scan.
            if self._is_terminal_control_instruction_record(irec):
                rec["terminal_instruction"] = irec
                rec["terminal_successors"] = succs
                break

            # Stop before entering next PAL block if known.
            ft = self.parse_addr(irec.get("fallthrough"))
            if ft is None:
                rec["terminal_instruction"] = irec
                rec["terminal_successors"] = succs
                break

            if next_block is not None and ft >= next_block and ft != start:
                # The current instruction is effectively the last raw instruction
                # before the next PAL/HF block.
                rec["terminal_instruction"] = irec
                rec["terminal_successors"] = succs
                rec["scan_notes"].append(
                    "stopped before next PAL block %s" % self.fmt_addr(next_block)
                )
                break

            cur = ft

        if rec["terminal_instruction"] is None and rec["instructions"]:
            rec["terminal_instruction"] = rec["instructions"][-1]
            rec["terminal_successors"] = self.raw_successors_from_instruction_record(rec["terminal_instruction"])
            rec["scan_notes"].append("max/implicit terminal used")

        return rec

    def raw_successors_from_instruction_record(self, irec):
        """
        Raw successor set for a single terminal instruction.

        For conditional branch instructions, Ghidra usually gives flow target(s)
        and fallthrough. For unconditional branches, fallthrough is often None.
        For non-branch instructions, this is just fallthrough.
        """
        out = []

        for f in irec.get("flows", []) or []:
            if f is not None:
                out.append(f)

        ft = irec.get("fallthrough")
        if ft is not None:
            out.append(ft)

        # Preserve order but dedupe.
        seen = set()
        dedup = []
        for x in out:
            if x in seen:
                continue
            seen.add(x)
            dedup.append(x)

        return dedup

    def format_raw_pcode_op(self, op):

        d = {
            "repr": None,
            "opcode": None,
            "output": None,
            "inputs": [],
            "seqnum": None,
        }

        try:
            d["repr"] = str(op)
        except Exception:
            d["repr"] = None

        try:
            d["opcode"] = str(op.getOpcode())
        except Exception:
            try:
                d["opcode"] = str(op.getMnemonic())
            except Exception:
                d["opcode"] = None

        try:
            out = op.getOutput()
            d["output"] = self.format_varnode(out)
        except Exception:
            d["output"] = None

        try:
            n = op.getNumInputs()
            d["inputs"] = [self.format_varnode(op.getInput(i)) for i in range(n)]
        except Exception:
            d["inputs"] = []

        try:
            d["seqnum"] = str(op.getSeqnum())
        except Exception:
            d["seqnum"] = None

        return d

    def format_varnode(self, v):

        if v is None:
            return None

        d = {
            "repr": None,
            "space": None,
            "offset": None,
            "size": None,
            "addr": None,
            "is_address": None,
            "is_constant": None,
            "is_register": None,
            "is_unique": None,
        }

        try:
            d["repr"] = str(v)
        except Exception:
            d["repr"] = None

        try:
            a = v.getAddress()
            d["addr"] = self.fmt_addr(a)
            d["space"] = str(a.getAddressSpace().getName())
            d["offset"] = int(a.getOffset())
        except Exception:
            d["addr"] = None

        try:
            d["size"] = int(v.getSize())
        except Exception:
            d["size"] = None

        for attr, meth in (
            ("is_address", "isAddress"),
            ("is_constant", "isConstant"),
            ("is_register", "isRegister"),
            ("is_unique", "isUnique"),
        ):
            try:
                d[attr] = bool(getattr(v, meth)())
            except Exception:
                d[attr] = None

        return d

    # ---------------------------------------------------------
    # HIGHFUNCTION / PAL BLOCK RECORDS
    # ---------------------------------------------------------

    def hf_record(self, addr_int):

        rec = {
            "addr": self.fmt_addr(addr_int),
            "pal_block_found": False,
            "pal_block_addr": None,
            "pal_ops": [],
            "pal_terminator": None,
            "pal_raw_out": [],
            "cfg_successors": [],
            "cfg_edges": [],
            "block_obj": None,
        }

        block = self.find_pal_block(addr_int)

        if block is None:
            return rec

        rec["block_obj"] = block
        rec["pal_block_found"] = True
        rec["pal_block_addr"] = self.fmt_addr(getattr(block, "addr", None))

        for op in self._as_list(getattr(block, "ops", None)):
            rec["pal_ops"].append(self.format_pal_op(op))

        term = getattr(block, "terminator", None)
        if term is not None:
            rec["pal_terminator"] = self.format_pal_op(term)

        for ro in self._as_list(getattr(block, "raw_out", None) or getattr(block, "raw_edges", None)):
            rec["pal_raw_out"].append(self.safe_dict(ro))

        cfg_node = None
        if self._cfg_nodes:
            cfg_node = self._cfg_nodes.get(getattr(block, "addr", None))

        if cfg_node is None:
            cfg_node = getattr(block, "cfg_node", None)

        if cfg_node is not None:
            for s in self._as_list(getattr(cfg_node, "successors", None)):
                rec["cfg_successors"].append(self.fmt_addr(getattr(s, "addr", None)))

            for e in self._as_list(getattr(cfg_node, "out_edges", None)):
                dst = getattr(e, "dst", None)
                rec["cfg_edges"].append({
                    "dst": self.fmt_addr(getattr(dst, "addr", None)),
                    "role": getattr(e, "role", None),
                    "raw_type": getattr(e, "raw_type", None),
                    "explicit_target": bool(getattr(e, "explicit_target", False) or getattr(e, "is_explicit_target", False)),
                    "fallthrough": bool(getattr(e, "fallthrough", False) or getattr(e, "is_fallthrough", False)),
                    "backedge": bool(getattr(e, "is_backedge", False) or getattr(e, "backedge", False)),
                    "loop_exit": bool(getattr(e, "is_loop_exit", False) or getattr(e, "loop_exit", False)),
                    "branch_target": self.fmt_addr(getattr(e, "branch_target", None) or getattr(e, "branch_target_addr", None)),
                })

        return rec

    def format_pal_op(self, op):

        d = {
            "opcode": getattr(op, "opcode", None),
            "output": self.format_pal_var(getattr(op, "output", None)),
            "inputs": [self.format_pal_var(v) for v in self._as_list(getattr(op, "inputs", None))],
            "cond": self.format_pal_var(getattr(op, "condition", None)),
            "repr": None,
        }

        try:
            d["repr"] = str(op)
        except Exception:
            d["repr"] = None

        return d

    def format_pal_var(self, v):

        if v is None:
            return None

        return {
            "sid": getattr(v, "ssa_id", None),
            "name": getattr(v, "name", None),
            "space": getattr(v, "space", None),
            "offset": getattr(v, "offset", None),
            "size": getattr(v, "size", None),
            "var_type": getattr(v, "var_type", None),
            "is_const": bool(getattr(v, "is_constant", False)),
            "is_temp": bool(getattr(v, "is_temp", False)),
            "is_stack": bool(getattr(v, "is_stack", False)),
            "is_global": bool(getattr(v, "is_global", False)),
            "is_function": bool(getattr(v, "is_function", False)),
        }

    def safe_dict(self, obj):

        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if isinstance(v, (str, int, float, bool)) or v is None:
                    out[k] = v
                else:
                    out[k] = str(v)
            return out

        return {"repr": str(obj)}

    # ---------------------------------------------------------
    # COMPARISON
    # ---------------------------------------------------------

    def compare_record(self, raw_block, hf):

        verdict = {
            "raw_terminal_successors": raw_block.get("terminal_successors", []),
            "hf_branch_targets": [],
            "notes": [],
            "status": "unknown",
        }

        for e in hf.get("cfg_edges", []) or []:
            dst = e.get("dst")
            if dst is not None:
                verdict["hf_branch_targets"].append(dst)

        raw_targets = set(raw_block.get("terminal_successors", []) or [])
        hf_targets = set(verdict["hf_branch_targets"])

        if not hf.get("pal_block_found"):
            verdict["status"] = "no_hf_block"
            verdict["notes"].append("No PAL/HighFunction block mapped to this address.")
            return verdict

        if not raw_block.get("terminal_instruction"):
            verdict["status"] = "no_raw_terminal"
            verdict["notes"].append("No raw terminal instruction found in block scan.")
            return verdict

        # It is common for raw branch/fallthrough targets to point to
        # non-HF-block addresses in short linear stubs. Resolve those stubs
        # conservatively before comparing against HighFunction CFG.
        current_block = hf.get("block_obj")
        normalized_raw = set()
        for r in raw_targets:
            normalized_raw.add(
                self._resolve_raw_successor_to_hf_target(
                    r,
                    current_block=current_block,
                    depth=0,
                )
            )

        missing = sorted(list(normalized_raw - hf_targets))
        extra = sorted(list(hf_targets - normalized_raw))

        verdict["normalized_raw_successors"] = sorted(normalized_raw)

        if not missing and not extra:
            verdict["status"] = "successors_match"
        else:
            verdict["status"] = "successors_differ"
            if missing:
                verdict["notes"].append("Raw successor(s) missing from HF/PAL CFG: %s" % missing)
            if extra:
                verdict["notes"].append("HF/PAL successor(s) not seen in raw terminal successors: %s" % extra)

        # Flag target mismatch records for inspection.
        for ro in hf.get("pal_raw_out", []) or []:
            bt = ro.get("branch_target_addr")
            dst = ro.get("dst_addr")
            if bt is not None and dst is not None:
                try:
                    # Do not call this fatal; branch target may point inside a
                    # block that maps to dst after normalization.
                    if int(bt) != int(dst) and ro.get("explicit_branch_target"):
                        verdict["notes"].append(
                            "PAL raw_out explicit target differs from dst: branch_target=%s dst=%s" %
                            (self.fmt_addr(bt), self.fmt_addr(dst))
                        )
                except Exception:
                    pass

        return verdict

    # ---------------------------------------------------------
    # RUN / PRINT
    # ---------------------------------------------------------

    def run(self, addresses):

        self.report = []

        for a in addresses:

            ai = self.parse_addr(a)
            if ai is None:
                self.errors.append({"addr": a, "error": "invalid address"})
                continue

            hf = self.hf_record(ai)
            raw_block = self.raw_block_record(ai, hf.get("block_obj"))
            cmp = self.compare_record(raw_block, hf)

            # Remove raw Python object before storing.
            hf_public = dict(hf)
            hf_public.pop("block_obj", None)

            self.report.append({
                "addr": self.fmt_addr(ai),
                "raw_block": raw_block,
                "highfunction": hf_public,
                "comparison": cmp,
            })

        if self.pal is not None:
            try:
                self.pal.raw_audit = self.report
            except Exception:
                pass

        return self.report

    def print_report(self, verbose=True):

        print("\n" + "=" * 72)
        print("PALRAW AUDIT v0.3 :: raw instruction BLOCK p-code vs HF/PAL CFG")
        print("=" * 72)

        for item in self.report:

            addr = item["addr"]
            raw = item["raw_block"]
            hf = item["highfunction"]
            cmp = item["comparison"]

            term = raw.get("terminal_instruction") or {}

            print("\n--- %s ---" % addr)
            print("Raw block  :", raw.get("block_start"), "-> next", raw.get("next_block_start"))
            print("Instr count:", len(raw.get("instructions", []) or []))
            print("Terminal   :", term.get("addr"), term.get("assembly"))
            print("Raw succs  :", raw.get("terminal_successors"))
            print("Norm succs :", cmp.get("normalized_raw_successors"))
            print("HF block   :", hf.get("pal_block_addr"))
            print("CFG edges  :", [
                "%s role=%s raw=%s" % (e.get("dst"), e.get("role"), e.get("raw_type"))
                for e in hf.get("cfg_edges", [])
            ])
            print("STATUS     :", cmp.get("status"))

            for n in cmp.get("notes", []) or []:
                print("NOTE       :", n)

            if verbose:
                print("Raw instructions:")
                for irec in raw.get("instructions", []) or []:
                    print("   %s  %s" % (irec.get("addr"), irec.get("assembly")))

                print("Terminal raw p-code:")
                for op in term.get("raw_pcode", []) or []:
                    print("   ", op.get("repr") or op)

                print("HF/PAL ops :")
                for op in hf.get("pal_ops", []) or []:
                    print("   ", self.compact_pal_op(op))

                if hf.get("pal_terminator"):
                    print("HF/PAL term:")
                    print("   ", self.compact_pal_op(hf.get("pal_terminator")))

        print("\n" + "=" * 72)

    def compact_pal_op(self, op):

        if not op:
            return None

        def vfmt(v):
            if v is None:
                return "None"
            if v.get("is_const"):
                try:
                    return hex(int(v.get("offset")))
                except Exception:
                    return str(v.get("offset"))
            return v.get("name") or v.get("sid") or str(v)

        out = vfmt(op.get("output"))
        ins = ", ".join(vfmt(v) for v in op.get("inputs") or [])
        cond = vfmt(op.get("cond"))

        if cond != "None":
            return "%s [%s] -> %s cond=%s" % (op.get("opcode"), ins, out, cond)

        return "%s [%s] -> %s" % (op.get("opcode"), ins, out)
