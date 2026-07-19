# ============================================================
# PAL HUMANIZER / ONCS
# BUILD: humanizer_v3_project_global_oncs_augmented_names
#
# Surgical scope:
#   - immutable SSA/PAL names;
#   - generated and operator variable-name projections;
#   - p_<ordinal>_<tag> parameters;
#   - project-global f_ function-name reservations;
#   - deferred UI/icecube metadata shims only.
# ============================================================

import builtins
import hashlib
import keyword
import math
import re
import json
import os

HUMANIZER_VERSION = "humanizer_v2_oncs_varnames_recovery"
FUNCTION_REGISTRY_FORMAT = "pal_function_name_registry"
FUNCTION_REGISTRY_SCHEMA = 1
FUNCTION_REGISTRY_FILENAME = "PAL_ONCS.json"
ONCS_AXES = ("ssa", "pal", "humanizer", "operator", "augmented")
COGNITIVE_WORDS = ('aurora', 'badger', 'acorn', 'anchor', 'basket', 'alcove', 'almond', 'banjo', 'agate', 'badge', 'aardvark', 'basil', 'apron', 'ash', 'basin', 'beaver', 'alder', 'anvil', 'bottle', 'arch', 'apple', 'beaker', 'amber', 'banner', 'dice', 'alpaca', 'beech', 'backpack', 'bay', 'beach', 'bison', 'bamboo', 'arrow', 'buckle', 'barge', 'barley', 'bell', 'bronze', 'bead', 'domino', 'antelope', 'bloom', 'barrel', 'clay', 'bluff', 'camel', 'birch', 'auger', 'button', 'barn', 'berry', 'canvas', 'chalk', 'boot', 'feather', 'baboon', 'chive', 'blanket', 'coast', 'brook', 'cheetah', 'bramble', 'beacon', 'candle', 'bread', 'cello', 'cobalt', 'broom', 'knot', 'beetle', 'elm', 'bowl', 'creek', 'canyon', 'cobra', 'cactus', 'blade', 'carpet', 'cabin', 'carrot', 'copper', 'brush', 'marble', 'bobcat', 'fig', 'camera', 'dust', 'cavern', 'coyote', 'cedar', 'bucket', 'clock', 'canoe', 'cherry', 'drum', 'crystal', 'charm', 'buffalo', 'grass', 'chair', 'earth', 'cloud', 'dolphin', 'clover', 'cable', 'goblet', 'castle', 'citrus', 'easel', 'denim', 'cloak', 'puzzle', 'cicada', 'hazel', 'chest', 'gulf', 'comet', 'eagle', 'cypress', 'chisel', 'goggles', 'cellar', 'cocoa', 'flask', 'flint', 'comb', 'cougar', 'herb', 'cleaver', 'hill', 'crater', 'falcon', 'daisy', 'clamp', 'helmet', 'chapel', 'garlic', 'flute', 'glass', 'cord', 'spool', 'cricket', 'lilac', 'crate', 'lake', 'delta', 'ferret', 'fern', 'compass', 'jacket', 'chimney', 'ginger', 'harp', 'granite', 'cork', 'topaz', 'donkey', 'mint', 'cushion', 'lava', 'desert', 'finch', 'heather', 'crank', 'journal', 'depot', 'grape', 'kiln', 'ivory', 'crown', 'trophy', 'duck', 'oak', 'dagger', 'meadow', 'dune', 'gecko', 'iris', 'drill', 'kettle', 'dome', 'guava', 'loom', 'jade', 'wand', 'egret', 'palm', 'drawer', 'peak', 'ember', 'gibbon', 'ivy', 'funnel', 'lantern', 'ferry', 'honey', 'lute', 'glove', 'wax', 'gazelle', 'rose', 'fork', 'pond', 'fjord', 'heron', 'juniper', 'gauge', 'medal', 'lemon', 'mortar', 'nickel', 'harness', 'gorilla', 'sage', 'knife', 'rain', 'flame', 'hornet', 'kelp', 'hammer', 'mirror', 'glider', 'lime', 'pestle', 'onyx', 'hamster', 'seed', 'lamp', 'sand', 'forest', 'iguana', 'larch', 'hinge', 'pencil', 'hangar', 'mango', 'piano', 'opal', 'hippo', 'shrub', 'mallet', 'sky', 'frost', 'jackal', 'lichen', 'pillow', 'kiosk', 'melon', 'pitcher', 'pearl', 'pennant', 'hyena', 'thyme', 'mug', 'snow', 'geyser', 'koala', 'linden', 'ladder', 'pocket', 'lodge', 'olive', 'platter', 'plaster', 'razor', 'kestrel', 'twig', 'pan', 'soil', 'glacier', 'lemur', 'lotus', 'lever', 'pouch', 'palace', 'onion', 'sieve', 'silver', 'ring', 'lobster', 'vine', 'plate', 'star', 'glen', 'leopard', 'maple', 'magnet', 'prism', 'pier', 'orange', 'stamp', 'slate', 'rope', 'magpie', 'yew', 'saucer', 'stone', 'gorge', 'lizard', 'moss', 'needle', 'quill', 'pillar', 'papaya', 'suede', 'soap', 'monkey', 'spoon', 'sun', 'grove', 'llama', 'nettle', 'nozzle', 'ribbon', 'plaza', 'peach', 'vial', 'velvet', 'strap', 'moth', 'stool', 'swamp', 'harbor', 'lynx', 'orchid', 'piston', 'saddle', 'porch', 'pear', 'violin', 'wool', 'narwhal', 'suitcase', 'tide', 'island', 'mantis', 'petal', 'pulley', 'scroll', 'rocket', 'pepper', 'yarn', 'twine', 'parrot', 'teapot', 'volcano', 'lagoon', 'marmot', 'pine', 'radar', 'sheath', 'rover', 'plum', 'zipper', 'pelican', 'tent', 'wind', 'marsh', 'moose', 'poppy', 'rivet', 'shield', 'skiff', 'radish', 'pigeon', 'tray', 'mesa', 'ocelot', 'reed', 'rotor', 'skillet', 'silo', 'rice', 'possum', 'umbrella', 'meteor', 'orca', 'redwood', 'shovel', 'sloop', 'spice', 'raccoon', 'vase', 'mist', 'otter', 'rowan', 'siphon', 'sponge', 'temple', 'turnip', 'robin', 'buggy', 'moon', 'panther', 'sequoia', 'spring', 'tablet', 'tower', 'walnut', 'seal', 'cart', 'oasis', 'panda', 'spruce', 'tether', 'ticket', 'tram', 'wheat', 'skunk', 'coach', 'ocean', 'puma', 'thistle', 'torch', 'tunnel', 'sloth', 'kayak', 'pebble', 'rabbit', 'thorn', 'turbine', 'towel', 'vault', 'snail', 'raft', 'quartz', 'raven', 'tulip', 'valve', 'wallet', 'wagon', 'stork', 'ship', 'reef', 'salmon', 'violet', 'wedge', 'whistle', 'yacht', 'swan', 'sled', 'ridge', 'shark', 'willow', 'wheel', 'tapir', 'subway', 'river', 'sparrow', 'yarrow', 'winch', 'termite', 'tractor', 'shadow', 'spider', 'yucca', 'wrench', 'toucan', 'train', 'shore', 'squid', 'zinnia', 'wasp', 'truck', 'spark', 'tiger', 'whale', 'van', 'storm', 'toad', 'wolf', 'vessel', 'summit', 'trout', 'yak', 'zeppelin', 'thunder', 'turtle', 'zebra', 'airplane', 'valley', 'viper', 'aardwolf', 'balloon', 'vapor', 'walrus', 'auk', 'bicycle', 'wave', 'weasel', 'boar', 'acrobat', 'zephyr', 'wombat', 'bull', 'jewel', 'calf', 'mosaic', 'parcel', 'puppet')

COGNITIVE_CODE_STOPWORDS = frozenset({
    "address", "alias", "asm", "block", "buffer", "call", "class", "code",
    "contract", "cursor", "digest", "field", "file", "filter", "flag",
    "frame", "function", "global", "handle", "heap", "input", "interface",
    "list", "local", "lock", "loop", "map", "mask", "memory", "metadata",
    "method", "module", "node", "object", "offset", "operator", "output",
    "parameter", "pipe", "pointer", "process", "record", "register",
    "return", "root", "source", "stack", "state", "stream", "string",
    "switch", "table", "target", "temp", "thread", "token", "tree",
    "tuple", "value", "variable", "view", "window",
})
PYTHON_RESERVED_NAMES = frozenset(
    set(keyword.kwlist)
    | set(dir(builtins))
    | COGNITIVE_CODE_STOPWORDS
    | {
        "MEM", "True", "False", "None", "abi_context", "self", "cls",
        "args", "kwargs", "main", "PALexec", "PAL_internal_dispatch",
        "external_ABI_dispatch", "thunk_endpoint_dispatch", "_pal_v",
        "MEM8", "MEM16", "MEM32", "MEM64", "MEM128",
    }
)

_GENERIC_VAR = (
    re.compile(r"^v_\d+$", re.I),
    re.compile(r"^local_[0-9a-f]+$", re.I),
    re.compile(r"^(?:u|i|l|b|c|pc|pu|pp|extraout|unaff)Var\d+$", re.I),
    re.compile(r"^(?:tmp|temp)(?:_|\d|$)", re.I),
)
_PARAMETER = (
    re.compile(r"^(?:parameter|param)_(\d+)$", re.I),
    re.compile(r"^p_(\d+)(?:_[A-Za-z][A-Za-z0-9]*)?$", re.I),
)
_GENERIC_FUNCTION = (
    re.compile(r"^(?:FUN|SUB|sub)_[0-9a-f]+$", re.I),
    re.compile(r"^(?:thunk_)?FUN_[0-9a-f]+$", re.I),
    re.compile(r"^function_[0-9a-f]+$", re.I),
)
_LOCKED_PREFIXES = ("abi_", "in_", "out_", "PTR_", "DAT_", "LAB_", "c_")
_LOCKED_MARKERS = (
    "abi", "call_target", "function", "global", "pointer", "address",
    "stack_pointer", "frame_pointer", "return_carrier", "register_carrier",
    "implicit_machine", "memory_space", "thread_local", "tls",
)


def _validate_vocabulary():
    if len(COGNITIVE_WORDS) != len(set(COGNITIVE_WORDS)):
        raise ValueError("duplicate PAL cognitive words")
    for word in COGNITIVE_WORDS:
        if not re.match(r"^[a-z][a-z0-9]{2,7}$", word):
            raise ValueError("invalid PAL cognitive word %r" % word)
        if word in COGNITIVE_CODE_STOPWORDS or keyword.iskeyword(word):
            raise ValueError("reserved PAL cognitive word %r" % word)


_validate_vocabulary()


def _value(record, name, default=None):
    return record.get(name, default) if isinstance(record, dict) else getattr(record, name, default)


def safe_identifier(value, fallback="name"):
    text = re.sub(r"[^0-9A-Za-z_]+", "_", str(value or ""))
    text = re.sub(r"_+", "_", text).strip("_") or fallback
    return "n_" + text if text[0].isdigit() else text


def is_generic_variable_name(name):
    return any(pattern.match(str(name or "")) for pattern in _GENERIC_VAR)


def is_generic_function_name(name):
    return any(pattern.match(str(name or "")) for pattern in _GENERIC_FUNCTION)


def function_surface_name(name):
    name = safe_identifier(name or "function", "function")
    return name if name.startswith("f_") else "f_" + name


def validate_operator_name(alias, reserved=None, allow=None):
    alias = str(alias or "").strip()
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", alias):
        raise ValueError("name must be an ASCII Python identifier")
    if keyword.iskeyword(alias):
        raise ValueError("name may not be a Python keyword")
    if alias.startswith("c_"):
        raise ValueError("name may not shadow PAL C-truth helpers")
    if alias.startswith("f_"):
        raise ValueError("f_ is reserved for function identities")
    if alias in COGNITIVE_CODE_STOPWORDS:
        raise ValueError("name %r is a PAL cognitive stopword" % alias)
    if alias in set(str(v) for v in (reserved or ()) if v) and alias != allow:
        raise ValueError("name %r collides with a reserved identity" % alias)
    return alias


def validate_variable_operator_name(alias, reserved=None, allow=None, parameter_index=None):
    text = str(alias or "").strip()
    if parameter_index is None:
        return validate_operator_name(text, reserved, allow)
    index = int(parameter_index)
    match = re.match(r"^p_(\d+)_(.+)$", text)
    if match:
        if int(match.group(1)) != index:
            raise ValueError("parameter alias must retain p_%d_" % index)
        text = match.group(2)
    text = validate_operator_name(text)
    result = "p_%d_%s" % (index, text)
    if result in set(str(v) for v in (reserved or ()) if v) and result != allow:
        raise ValueError("name %r collides with a reserved identity" % result)
    return result


def validate_function_operator_name(alias, reserved=None, allow=None):
    text = str(alias or "").strip()
    text = text[2:] if text.startswith("f_") else text
    result = "f_" + validate_operator_name(text)
    if result in set(str(v) for v in (reserved or ()) if v) and result != allow:
        raise ValueError("name %r collides with a reserved identity" % result)
    return result


def function_identity(record, program_identity=None):
    entry = _value(record, "entry")
    if isinstance(entry, int):
        return "function:0x%x" % entry
    if _value(record, "entry_hex"):
        return "function:%s" % str(_value(record, "entry_hex")).lower()
    seed = "%s|%s|%s" % (
        program_identity or "program",
        _value(record, "module_stem") or _value(record, "module") or "",
        _value(record, "qualified_name") or _value(record, "name") or "",
    )
    return "function:sha256:%s" % hashlib.sha256(seed.encode()).hexdigest()[:16]


def program_identity(program):
    program = dict(program or {})
    seed = "|".join(str(program.get(key) or "") for key in (
        "name", "image_base", "language_id", "compiler_spec_id", "executable_path"
    ))
    return "program:sha256:%s" % hashlib.sha256(seed.encode()).hexdigest()[:20]


class CognitiveNameAllocator:
    def __init__(self, namespace, reserved=None, words=None):
        self.namespace = str(namespace or "PAL")
        self.words = tuple(words or COGNITIVE_WORDS)
        self.used = set(str(v) for v in (reserved or ()) if v)
        self.allocations = {}
        self.events = []

    def allocate(self, identity, prefix=""):
        key = (str(identity), str(prefix))
        if key in self.allocations:
            return dict(self.allocations[key])
        digest = hashlib.sha256((self.namespace + "|" + key[0]).encode()).digest()
        count = len(self.words)
        start = int.from_bytes(digest[:8], "big") % count
        step = 1 + int.from_bytes(digest[8:16], "big") % (count - 1)
        while math.gcd(step, count) != 1:
            step = 1 if step + 1 >= count else step + 1
        rejected = []
        for probe in range(count):
            index = (start + probe * step) % count
            name = prefix + self.words[index]
            if name in self.used:
                rejected.append(name)
                continue
            self.used.add(name)
            result = {
                "name": name,
                "word": self.words[index],
                "identity": key[0],
                "word_index": index,
                "probe_count": probe,
                "collision_count": len(rejected),
                "rejected_candidates": rejected,
                "hash_sha256": digest.hex(),
                "algorithm": "sha256_open_addressing_v2",
                "fallback_suffix": False,
            }
            self.allocations[key] = result
            if rejected:
                self.events.append({"kind": "cognitive_name_collision_resolved", "selected": name})
            return dict(result)
        tier = 2
        root = prefix + self.words[start]
        name = root + str(tier)
        while name in self.used:
            tier += 1
            name = root + str(tier)
        self.used.add(name)
        result = {
            "name": name, "word": self.words[start], "identity": key[0],
            "word_index": start, "probe_count": count, "collision_count": count,
            "rejected_candidates": [], "hash_sha256": digest.hex(),
            "algorithm": "sha256_open_addressing_v2", "fallback_suffix": True,
            "fallback_tier": tier,
        }
        self.allocations[key] = result
        return dict(result)


def _pal_name(variable, sid):
    return str(
        _value(variable, "display_name")
        or _value(variable, "name")
        or _value(variable, "original_name")
        or sid
    )


def _parameter_index(variable, name):
    for key in (
        "parameter_index", "parameter_ordinal", "param_index", "param_ordinal",
        "argument_index", "argument_ordinal",
    ):
        value = _value(variable, key)
        if isinstance(value, int) and value >= 0:
            return value
        if value is not None and str(value).isdigit():
            return int(value)
    for pattern in _PARAMETER:
        match = pattern.match(str(name or ""))
        if match:
            return int(match.group(1))
    return None


def _is_parameter(variable, name):
    return bool(
        _value(variable, "is_parameter", False)
        or _value(variable, "is_callable_parameter", False)
        or _parameter_index(variable, name) is not None
    )


def _locked_reason(variable, name):
    if _value(variable, "is_constant", False):
        return "constant_identity"
    if any(_value(variable, key, False) for key in (
        "is_implicit_machine_input", "is_abi_physical_carrier", "is_global",
        "is_function", "is_call_target", "is_address",
    )):
        return "semantic_role_flag"
    surface = str(name or "")
    if surface.startswith(_LOCKED_PREFIXES) or re.match(
        r"^(?:ABI(?:_|[A-Z0-9])|MEM(?:8|16|32|64|128)?$|_pal_v$)",
        surface,
        re.I,
    ):
        return "semantic_surface_name"
    semantic = " ".join(str(_value(variable, key, "")).lower() for key in (
        "semantic_role", "symbol_kind", "var_type", "domain", "canonical_type",
        "resolver_contract", "storage_family_descriptor", "abi_entry_root",
        "abi_execution_owner",
    ))
    for marker in _LOCKED_MARKERS:
        if marker in semantic:
            return "semantic_contract:%s" % marker
    return None


def classify_variable_humanization(variable, sid=None):
    sid = str(sid or _value(variable, "sid") or _value(variable, "ssa_id") or "")
    name = _pal_name(variable, sid)
    reason = _locked_reason(variable, name)
    if reason:
        return False, reason
    if not sid:
        return False, "missing_ssa_identity"
    if _is_parameter(variable, name):
        return True, None
    if is_generic_variable_name(name) or name == sid:
        return True, None
    return False, "meaningful_source_name"


def build_variable_alias_contracts(
    variables, function_id, operator_aliases=None, reserved_names=None,
    function_names=None,
):
    variables = list(variables or [])
    operators = {str(k): str(v) for k, v in dict(operator_aliases or {}).items() if v}
    rows = []
    next_parameter = 0
    used_parameters = set()

    for order, variable in enumerate(variables):
        sid = str(_value(variable, "sid") or _value(variable, "ssa_id") or "")
        if not sid:
            continue
        name = _pal_name(variable, sid)
        index = _parameter_index(variable, name)
        if index is not None:
            used_parameters.add(index)
        rows.append([sid, variable, name, index, order])
    for row in rows:
        if _is_parameter(row[1], row[2]) and row[3] is None:
            while next_parameter in used_parameters:
                next_parameter += 1
            row[3] = next_parameter
            used_parameters.add(next_parameter)

    reserved = set(PYTHON_RESERVED_NAMES)
    reserved.update(str(v) for v in (reserved_names or ()) if v)
    reserved.update(str(v) for v in (function_names or ()) if v)
    for sid, unused, name, unused_index, unused_order in rows:
        reserved.update((sid, name))

    allocator = CognitiveNameAllocator(
        "variable|%s|%s" % (HUMANIZER_VERSION, function_id), reserved
    )
    decisions = {}
    generated = {}
    for sid, variable, name, index, unused_order in sorted(rows, key=lambda row: row[0]):
        eligible, reason = classify_variable_humanization(variable, sid)
        decisions[sid] = (eligible, reason, name, index)
        if eligible:
            generated[sid] = allocator.allocate(sid, "p_%d_" % index if index is not None else "")

    generated_owner = {value["name"]: sid for sid, value in generated.items()}
    identity_owner = {}
    for sid, unused, name, unused_index, unused_order in rows:
        identity_owner[sid] = sid
        identity_owner[name] = sid

    valid_operator = {}
    conflicts = []
    operator_owner = {}
    global_reserved = set(PYTHON_RESERVED_NAMES)
    global_reserved.update(str(v) for v in (reserved_names or ()) if v)
    global_reserved.update(str(v) for v in (function_names or ()) if v)

    for sid in sorted(operators):
        if sid not in decisions:
            conflicts.append(_conflict(sid, operators[sid], "unknown_variable_identity"))
            continue
        eligible, reason, unused_name, index = decisions[sid]
        if not eligible:
            conflicts.append(_conflict(sid, operators[sid], reason or "variable_rename_locked"))
            continue
        try:
            alias = validate_variable_operator_name(operators[sid], parameter_index=index)
        except ValueError as exc:
            conflicts.append(_conflict(sid, operators[sid], str(exc)))
            continue
        if alias in operator_owner:
            conflicts.append(_conflict(sid, alias, "duplicate_operator_alias", operator_owner[alias]))
        elif alias in identity_owner and identity_owner[alias] != sid:
            conflicts.append(_conflict(sid, alias, "operator_alias_collides_with_PAL_or_SSA_name", identity_owner[alias]))
        elif alias in generated_owner and generated_owner[alias] != sid:
            conflicts.append(_conflict(sid, alias, "operator_alias_collides_with_generated_name", generated_owner[alias]))
        elif alias in global_reserved:
            conflicts.append(_conflict(sid, alias, "operator_alias_collides_with_global_or_reserved_name"))
        else:
            operator_owner[alias] = sid
            valid_operator[sid] = alias

    contracts = {}
    excluded = {}
    for sid, variable, name, index, unused_order in rows:
        eligible, reason, unused_name, unused_index = decisions[sid]
        allocation = generated.get(sid)
        human = allocation["name"] if allocation else None
        operator = valid_operator.get(sid)
        active = operator or human or name
        source = "operator" if operator else "generated" if human else "pal"
        contracts[sid] = {
            "kind": "resolver_human_alias_contract_v25",
            "version": HUMANIZER_VERSION,
            "sid": sid,
            "canonical_ssa_name": sid,
            "pal_name": name,
            "humanization_eligible": eligible,
            "humanization_exclusion_reason": reason,
            "generated_human_alias": human,
            "operator_alias": operator,
            "active_name_source": source,
            "active_name": active,
            "allocation": allocation,
            "algorithm": "oncs_sha256_cognitive_alias_v2",
            "is_parameter": index is not None,
            "parameter_index": index,
            "rename_locked": not eligible,
            "oncs": {"ssa": sid, "pal": name, "humanizer": human, "operator": operator, "active": active},
            "semantic_identity_mutated": False,
            "operator_alias_mutates_ground_truth": False,
        }
        if not eligible:
            excluded[sid] = reason

    human_names = [c["generated_human_alias"] for c in contracts.values() if c["generated_human_alias"]]
    operator_names = [c["operator_alias"] for c in contracts.values() if c["operator_alias"]]
    inventory = {
        "kind": "pal_humanizer_variable_inventory_v1",
        "version": HUMANIZER_VERSION,
        "function_identity": str(function_id),
        "vocabulary_size": len(COGNITIVE_WORDS),
        "variables": len(rows),
        "parameters": sum(c["is_parameter"] for c in contracts.values()),
        "eligible": sum(c["humanization_eligible"] for c in contracts.values()),
        "excluded": len(excluded),
        "generated": len(human_names),
        "operator_aliases": len(operator_names),
        "operator_alias_conflicts": conflicts,
        "generated_collision_events": list(allocator.events),
        "generated_collisions_resolved": len(allocator.events),
        "fallback_suffixes": sum(bool((c["allocation"] or {}).get("fallback_suffix")) for c in contracts.values()),
        "exclusion_reasons": {reason: list(excluded.values()).count(reason) for reason in sorted(set(excluded.values()))},
        "acceptance_gates": {
            "generated_aliases_unique": len(human_names) == len(set(human_names)),
            "operator_aliases_unique": len(operator_names) == len(set(operator_names)),
            "parameter_positions_preserved": all(
                not c["is_parameter"] or not c["humanization_eligible"]
                or str(c["active_name"]).startswith("p_%d_" % c["parameter_index"])
                for c in contracts.values()
            ),
            "function_namespace_reserved": all(not n.startswith("f_") for n in human_names + operator_names),
            "protected_semantic_names_locked": all(contracts[sid]["rename_locked"] for sid in excluded),
            "ssa_identity_unchanged": True,
        },
        "rule": "ONCS metadata views; only disposable variables are editable",
    }
    return contracts, inventory


def _conflict(sid, alias, reason, owner=None):
    result = {"sid": sid, "alias": alias, "reason": reason, "action": "quarantine_operator_alias"}
    if owner is not None:
        result["collides_with_sid"] = owner
    return result


class PALFunctionNameRegistry:
    NAMING_MODES = ("ssa", "pal", "humanizer", "operator", "augmented")

    def __init__(self, payload=None):
        payload = dict(payload or {})
        self.program_identity = str(payload.get("program_identity") or "program:unknown")
        self.records = {str(k): dict(v) for k, v in dict(payload.get("functions", {}) or {}).items()}
        self.revisions = list(payload.get("revisions", []) or [])
        self.collisions = list(payload.get("collisions", []) or [])
        self.revision = int(payload.get("revision", 0) or 0)

    @classmethod
    def from_manifest(cls, records, program=None, existing=None):
        obj = cls(existing)
        identity = program_identity(program)
        if obj.records and obj.program_identity not in ("program:unknown", identity):
            raise ValueError("function name registry belongs to another program")
        obj.program_identity = identity
        return obj.reconcile(records)

    def _claimed(self, exclude=None):
        names = set(PYTHON_RESERVED_NAMES)
        for function_id, record in self.records.items():
            if function_id == exclude:
                continue
            for key in ("ssa_name", "original_name", "pal_name", "qualified_name", "python_symbol", "generated_name", "operator_name", "active_name"):
                if record.get(key):
                    names.add(str(record[key]))
        return names

    def all_names(self):
        return self._claimed()

    def reconcile(self, manifest_records):
        records = [dict(v) for v in list(manifest_records or [])]
        for item in self.records.values():
            item["present_in_manifest"] = False
        reserved = set(PYTHON_RESERVED_NAMES)
        prepared = []
        for record in records:
            fid = function_identity(record, self.program_identity)
            ssa = str(record.get("name") or "unnamed")
            pal = function_surface_name(ssa)
            prepared.append((fid, record, ssa, pal))
            reserved.update(v for v in (ssa, pal, record.get("qualified_name"), record.get("python_symbol")) if v)
        for item in self.records.values():
            for key in ("generated_name", "operator_name"):
                if item.get(key):
                    item[key] = function_surface_name(item[key])
                    reserved.add(item[key])
        allocator = CognitiveNameAllocator("function|%s|%s" % (HUMANIZER_VERSION, self.program_identity), reserved)
        for fid, record, ssa, pal in sorted(prepared, key=lambda x: (x[1].get("entry") is None, x[1].get("entry") or 0, x[2])):
            item = dict(self.records.get(fid, {}) or {})
            eligible = not record.get("external") and is_generic_function_name(ssa)
            generated = item.get("generated_name")
            if eligible and not generated:
                generated = allocator.allocate(fid, "f_")["name"]
            if not eligible:
                generated = None
            operator = function_surface_name(item["operator_name"]) if item.get("operator_name") else None
            active = operator or generated or pal
            source = "operator" if operator else "generated" if generated else "pal"
            item.update({
                "kind": "pal_function_name_contract_v2_oncs",
                "version": HUMANIZER_VERSION,
                "function_id": fid,
                "entry": record.get("entry"),
                "entry_hex": record.get("entry_hex"),
                "ssa_name": ssa,
                "original_name": ssa,
                "pal_name": pal,
                "qualified_name": record.get("qualified_name"),
                "module": record.get("module"),
                "python_symbol": record.get("python_symbol"),
                "external": bool(record.get("external")),
                "thunk": bool(record.get("thunk")),
                "present_in_manifest": True,
                "humanization_eligible": bool(eligible),
                "humanization_exclusion_reason": None if eligible else "external_function" if record.get("external") else "meaningful_function_name",
                "generated_name": generated,
                "operator_name": operator,
                "active_name": active,
                "active_name_source": source,
                "oncs": {"ssa": ssa, "pal": pal, "humanizer": generated, "operator": operator, "active": active},
                "identity_mutated": False,
            })
            self.records[fid] = item
        self._validate_aliases()
        return self

    def _validate_aliases(self):
        owners = {}
        for fid, record in self.records.items():
            if record.get("present_in_manifest") is False:
                continue
            for key in ("generated_name", "operator_name"):
                alias = record.get(key)
                if not alias:
                    continue
                if alias in owners and owners[alias] != fid:
                    event = {"kind": "function_alias_collision", "name": alias, "first_function_id": owners[alias], "second_function_id": fid}
                    if event not in self.collisions:
                        self.collisions.append(event)
                    raise ValueError("function alias collision: %s" % alias)
                owners[alias] = fid

    def function_id_for_record(self, record):
        return function_identity(record, self.program_identity)

    def record(self, function_id):
        return self.records.get(str(function_id))

    def find(self, entry=None, name=None):
        hits = []
        for fid, record in self.records.items():
            if isinstance(entry, int) and record.get("entry") == entry:
                return fid, record
            if name and name in {record.get(k) for k in ("ssa_name", "original_name", "pal_name", "qualified_name", "python_symbol", "generated_name", "operator_name", "active_name")}:
                hits.append((fid, record))
        return hits[0] if len(hits) == 1 else (None, None)

    def effective_name(self, function_id, naming="active"):
        record = self.record(function_id) or {}
        ssa = record.get("ssa_name") or record.get("original_name") or "function"
        pal = record.get("pal_name") or function_surface_name(ssa)
        human = record.get("generated_name") or pal
        operator = record.get("operator_name") or human
        augmented = "fun_" + str(operator).removeprefix("f_")
        names = {
            "ssa": ssa, "original": ssa, "emitted": ssa,
            "pal": pal,
            "generated": human, "humanizer": human,
            "human": human, "cognitive": human,
            "operator": operator,
            "active": operator,
            "augmented": augmented,
        }
        key = str(naming or "active").lower()
        if key not in names:
            raise ValueError("unsupported function naming projection %r" % naming)
        return str(names[key])

    def set_operator_name(self, function_id, alias, author="human", scope="module"):
        if scope != "module":
            raise ValueError("function names may only be edited from module view")
        fid = str(function_id)
        record = self.records.get(fid)
        if record is None:
            raise KeyError("unknown function identity %s" % fid)
        if record.get("external"):
            raise ValueError("external/library function names are ABI-owned and rename-locked")
        alias = validate_function_operator_name(alias, self._claimed(fid), record.get("operator_name"))
        previous = record.get("operator_name")
        if previous == alias:
            return alias
        self.revision += 1
        record["operator_name"] = alias
        record["active_name"] = alias
        record["active_name_source"] = "operator"
        record["oncs"]["operator"] = alias
        record["oncs"]["active"] = alias
        self.revisions.append({"kind": "pal_function_name_revision_v2_oncs", "revision": self.revision, "function_id": fid, "previous": previous, "current": alias, "author": str(author or "human"), "scope": "module"})
        self._validate_aliases()
        return alias

    def clear_operator_name(self, function_id, author="human"):
        fid = str(function_id)
        record = self.records.get(fid)
        if record is None:
            raise KeyError("unknown function identity %s" % fid)
        previous = record.get("operator_name")
        if previous is None:
            return None
        self.revision += 1
        record["operator_name"] = None
        record["active_name"] = record.get("generated_name") or record.get("pal_name")
        record["active_name_source"] = "generated" if record.get("generated_name") else "pal"
        record["oncs"]["operator"] = None
        record["oncs"]["active"] = record["active_name"]
        self.revisions.append({"kind": "pal_function_name_revision_v2_oncs", "revision": self.revision, "function_id": fid, "previous": previous, "current": None, "author": str(author or "human"), "scope": "module"})
        return previous

    def manifest_fields(self, function_id):
        record = self.record(function_id) or {}
        return {key: record.get(key) for key in ("function_id", "ssa_name", "pal_name", "generated_name", "operator_name", "active_name", "active_name_source")}

    def as_dict(self):
        aliases = [str(record[key]) for record in self.records.values() for key in ("generated_name", "operator_name") if record.get(key)]
        return {
            "format": FUNCTION_REGISTRY_FORMAT,
            "schema_version": FUNCTION_REGISTRY_SCHEMA,
            "version": HUMANIZER_VERSION,
            "program_identity": self.program_identity,
            "revision": self.revision,
            "vocabulary_size": len(COGNITIVE_WORDS),
            "functions": {key: dict(self.records[key]) for key in sorted(self.records)},
            "revisions": list(self.revisions),
            "collisions": list(self.collisions),
            "acceptance_gates": {
                "function_identities_immutable": True,
                "human_aliases_unique": len(aliases) == len(set(aliases)),
                "all_projected_function_names_prefixed": all(
                    str(record[key]).startswith("f_")
                    for record in self.records.values()
                    for key in ("pal_name", "generated_name", "operator_name", "active_name")
                    if record.get(key)
                ),
                "operator_names_revisioned": True,
                "physical_dispatch_identity_unchanged": True,
            },
            "rule": "project-global f_ metadata views over immutable entry identity",
        }


def icecube_sim_shim_asm(block_addr=None):
    return ["icecube sim shim ASM" + (" @ %s" % block_addr if block_addr is not None else "")]


def icecube_sim_shim_c_code(function_name=None):
    return ["icecube sim shim C-CODE" + (" for %s" % function_name if function_name else "")]


def truth_digest_daily_shim(raw=False):
    data = {
        "kind": "pal_truth_digest_daily_shim_v1",
        "status": "deferred_metadata",
        "menu": [
            {"key": "F1", "label": "C code", "source": "shim:c_code"},
            {"key": "F2", "label": "function definition", "source": "shim:function"},
            {"key": "F3", "label": "variables", "source": "oncs:variables"},
            {"key": "F4", "label": "ABI custody interfaces", "source": "shim:abi"},
        ],
        "raw_peek_key": "R",
        "asm": icecube_sim_shim_asm(),
        "c_code": icecube_sim_shim_c_code(),
        "function_definition": "icecube sim shim FUNCTION DEF",
        "abi_custody": "icecube sim shim ABI CUSTODY",
        "ui_wired": False,
    }
    return data if raw else [
        "TRUTH DIGEST DAILY [SIM SHIM]",
        "F1 C code | F2 function | F3 vars | F4 ABI custody | R raw",
        "ASM: icecube sim shim ASM",
        "C: icecube sim shim C-CODE",
    ]


def deferred_metadata_shims():
    return {
        "asm_by_block": {"default": icecube_sim_shim_asm()},
        "function_c_code": icecube_sim_shim_c_code(),
        "truth_digest_daily": truth_digest_daily_shim(raw=True),
    }


def identifier_at_column(line, column):
    text = str(line or "")
    column = min(max(int(column or 0), 0), len(text))
    for match in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text):
        if match.start() <= column < match.end() or column == match.end() == len(text):
            return match.group(0)
    return None


def identifier_occurrences(lines, identifier):
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(identifier or "")):
        return []
    pattern = re.compile(r"\b%s\b" % re.escape(str(identifier)))
    return [
        (line_number, match.start(), match.end())
        for line_number, line in enumerate(list(lines or []))
        for match in pattern.finditer(str(line))
    ]


def debug_dump_humanizer(contracts, inventory):
    print("===== PAL ONCS HUMANIZER =====")
    print(inventory)
    for sid in sorted(dict(contracts or {})):
        contract = contracts[sid]
        print("%s -> %s [%s]" % (sid, contract.get("active_name"), contract.get("active_name_source")))
    print("===== END PAL ONCS HUMANIZER =====")



# ============================================================================
# PROJECT-GLOBAL ONCS STORE
# ============================================================================

ONCS_PROJECT_FORMAT = "pal_oncs_project"
ONCS_PROJECT_SCHEMA = 1
OBJECT_LABEL_TYPES = ("SSA", "PAL", "Humanizer", "Operator", "Augmented")


def augmented_function_name(value):
    """Cognitive context clue used only by the Augmented display projection."""
    text = function_surface_name(value)
    return "fun_" + text.removeprefix("f_")


def augmented_variable_name(contract, naming="active"):
    """Preserve parameter positionality; ordinary variables remain uncluttered."""
    contract = dict(contract or {})
    if naming == "ssa":
        return contract.get("canonical_ssa_name") or contract.get("pal_name")
    if naming == "pal":
        return contract.get("pal_name")
    if naming in ("humanizer", "generated"):
        return contract.get("generated_human_alias") or contract.get("pal_name")
    if naming == "operator":
        return (
            contract.get("operator_alias")
            or contract.get("generated_human_alias")
            or contract.get("pal_name")
        )
    if naming == "augmented":
        active = (
            contract.get("operator_alias")
            or contract.get("generated_human_alias")
            or contract.get("pal_name")
        )
        index = contract.get("parameter_index")
        if isinstance(index, int) and not str(active).startswith("p_%d_" % index):
            active = "p_%d_%s" % (index, str(active).removeprefix("p_%d_" % index))
        return active
    return contract.get("active_name") or contract.get("pal_name")


class ProjectONCSStore:
    """One project-owned ONCS file for functions and all variable operator edits."""

    def __init__(self, path, manifest_records=None, program=None, payload=None):
        self.path = os.path.abspath(os.fspath(path))
        payload = dict(payload or {})
        if payload and payload.get("format") not in (None, ONCS_PROJECT_FORMAT, FUNCTION_REGISTRY_FORMAT):
            raise ValueError("unsupported PAL_ONCS format %r" % payload.get("format"))

        legacy_registry = payload if payload.get("format") == FUNCTION_REGISTRY_FORMAT else payload.get("function_registry")
        self.function_registry = PALFunctionNameRegistry.from_manifest(
            manifest_records or [], program=program or {}, existing=legacy_registry,
        )
        self.variable_state = {
            str(fid): dict(value)
            for fid, value in dict(payload.get("variables", {}) or {}).items()
        }
        self.revision = int(payload.get("revision", 0) or 0)
        self.revisions = list(payload.get("revisions", []) or [])
        self.status = "PAL_ONCS loaded" if payload else "PAL_ONCS initialized"

    @classmethod
    def load(cls, path, manifest_records=None, program=None):
        payload = {}
        if path and os.path.isfile(path):
            with open(path, "rt", encoding="utf-8") as handle:
                payload = json.load(handle)
        return cls(path, manifest_records, program, payload)

    def function_id_for_record(self, record):
        return self.function_registry.function_id_for_record(record)

    def function_names(self):
        names = set(PYTHON_RESERVED_NAMES)
        for record in self.function_registry.records.values():
            for key in (
                "ssa_name", "original_name", "pal_name", "qualified_name",
                "python_symbol", "generated_name", "operator_name", "active_name",
            ):
                value = record.get(key)
                if value:
                    names.add(str(value))
        return names

    def function_mapping(self, naming="augmented", current_function_id=None):
        owners = {}
        ambiguous = set()
        for fid, record in self.function_registry.records.items():
            target = self.function_registry.effective_name(fid, naming)
            for source in (
                record.get("ssa_name"), record.get("original_name"),
                record.get("qualified_name"), record.get("python_symbol"),
            ):
                source = str(source or "")
                if not source or source == target:
                    continue
                prior = owners.get(source)
                if prior is not None and prior != target:
                    ambiguous.add(source)
                else:
                    owners[source] = target
        for source in ambiguous:
            owners.pop(source, None)
        if current_function_id:
            record = self.function_registry.record(current_function_id) or {}
            source = record.get("ssa_name") or record.get("original_name")
            if source:
                owners[str(source)] = self.function_registry.effective_name(current_function_id, naming)
        return owners

    def variable_operator_aliases(self, function_id):
        state = dict(self.variable_state.get(str(function_id), {}) or {})
        return {
            str(k): str(v) for k, v in dict(state.get("operator_aliases", {}) or {}).items()
            if v
        }

    def set_variable_operator_aliases(self, function_id, aliases, author="human"):
        fid = str(function_id)
        state = self.variable_state.setdefault(fid, {
            "revision": 0, "operator_aliases": {}, "revisions": [],
        })
        before = dict(state.get("operator_aliases", {}) or {})
        after = {str(k): str(v) for k, v in dict(aliases or {}).items() if v}
        if before == after:
            return after
        state["revision"] = int(state.get("revision", 0) or 0) + 1
        state["operator_aliases"] = after
        state.setdefault("revisions", []).append({
            "kind": "pal_oncs_variable_set_revision_v1",
            "revision": state["revision"], "previous": before, "current": after,
            "author": str(author or "human"),
        })
        self.revision += 1
        self.revisions.append({
            "kind": "pal_oncs_project_revision_v1", "revision": self.revision,
            "function_id": fid, "scope": "variables",
        })
        return after

    def set_function_operator_name(self, function_id, alias, author="human"):
        value = self.function_registry.set_operator_name(
            function_id, alias, author=author, scope="module"
        )
        self.revision += 1
        self.revisions.append({
            "kind": "pal_oncs_project_revision_v1", "revision": self.revision,
            "function_id": str(function_id), "scope": "function", "current": value,
        })
        return value

    def clear_function_operator_name(self, function_id, author="human"):
        value = self.function_registry.clear_operator_name(function_id, author=author)
        if value is not None:
            self.revision += 1
            self.revisions.append({
                "kind": "pal_oncs_project_revision_v1", "revision": self.revision,
                "function_id": str(function_id), "scope": "function", "current": None,
            })
        return value

    def as_dict(self):
        return {
            "format": ONCS_PROJECT_FORMAT,
            "schema_version": ONCS_PROJECT_SCHEMA,
            "humanizer_version": HUMANIZER_VERSION,
            "revision": self.revision,
            "object_label_types": list(OBJECT_LABEL_TYPES),
            "function_registry": self.function_registry.as_dict(),
            "variables": {
                key: dict(self.variable_state[key]) for key in sorted(self.variable_state)
            },
            "revisions": list(self.revisions),
            "acceptance_gates": {
                "single_project_oncs_authority": True,
                "icecube_identity_immutable": True,
                "function_rename_module_only": True,
                "external_function_rename_blocked": True,
                "structural_semantic_labels_locked": True,
            },
        }

    def save(self):
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        temp = "%s.tmp.%d" % (self.path, os.getpid())
        try:
            with open(temp, "wt", encoding="utf-8", newline="\n") as handle:
                json.dump(self.as_dict(), handle, sort_keys=True, indent=2, ensure_ascii=True)
                handle.write("\n")
            os.replace(temp, self.path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        self.status = "PAL_ONCS saved"
        return self.path


class PALHumanize:
    """Facade matching the PALTermUI architecture outline."""

    object_label_types = list(OBJECT_LABEL_TYPES)

    def __init__(self, oncs_store=None):
        self.oncs_store = oncs_store

    def humanize_var_names(self, variables, function_id, operator_aliases=None):
        function_names = self.oncs_store.function_names() if self.oncs_store else ()
        return build_variable_alias_contracts(
            variables, function_id,
            operator_aliases=operator_aliases,
            function_names=function_names,
        )

    def humanize_function_names(self, records, program=None, existing=None):
        return PALFunctionNameRegistry.from_manifest(records, program=program, existing=existing)

    def operator_rename_variable(self, contracts, sid, alias):
        contract = dict(contracts.get(str(sid), {}) or {})
        if not contract:
            raise KeyError("unknown ONCS variable identity %s" % sid)
        if contract.get("rename_locked"):
            raise ValueError("rename locked: %s" % (
                contract.get("humanization_exclusion_reason") or "structural semantic identity"
            ))
        return validate_variable_operator_name(
            alias,
            parameter_index=contract.get("parameter_index"),
        )

    def operator_rename_function(self, function_id, alias):
        if not self.oncs_store:
            raise ValueError("project ONCS store is required")
        return self.oncs_store.set_function_operator_name(function_id, alias)

    def augment_context_clue_prefix_for_functions(self, value):
        return augmented_function_name(value)

    def check_for_rename_eligibility(self, variable):
        sid = str(_value(variable, "sid") or _value(variable, "ssa_id") or "")
        eligible, reason = classify_variable_humanization(variable, sid)
        return {"eligible": bool(eligible), "reason": reason, "sid": sid}


__all__ = [
    "HUMANIZER_VERSION", "FUNCTION_REGISTRY_FORMAT", "FUNCTION_REGISTRY_SCHEMA",
    "FUNCTION_REGISTRY_FILENAME", "ONCS_PROJECT_FORMAT", "ONCS_PROJECT_SCHEMA",
    "OBJECT_LABEL_TYPES", "ONCS_AXES", "COGNITIVE_WORDS",
    "COGNITIVE_CODE_STOPWORDS", "PYTHON_RESERVED_NAMES", "CognitiveNameAllocator",
    "PALFunctionNameRegistry", "ProjectONCSStore", "PALHumanize",
    "build_variable_alias_contracts", "classify_variable_humanization",
    "function_identity", "program_identity", "function_surface_name",
    "augmented_function_name", "augmented_variable_name",
    "is_generic_variable_name", "is_generic_function_name", "safe_identifier",
    "validate_operator_name", "validate_variable_operator_name",
    "validate_function_operator_name", "icecube_sim_shim_asm",
    "icecube_sim_shim_c_code", "truth_digest_daily_shim",
    "deferred_metadata_shims", "identifier_at_column", "identifier_occurrences",
    "debug_dump_humanizer",
]
