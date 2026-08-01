<img width="1564" height="1002" alt="image" src="https://github.com/user-attachments/assets/f105a443-aae2-42e4-b6bd-c12ede2aacec" />



# Quick Start

- in order to run pipeline commands you need to have Ghidra/PyGhidra installed
- you can use the JVM-free (no Ghidra needed) detached mode to still run and examine projects

## From the PAL repository root:

```
./pal_env.sh
./pal pipeline game
./pal termui
./pal exec
```


---

`./pal termui` opens the PAL terminal workbench. 

`./pal pipeline` game decompiles and publishes the included ASCII Lunar Lander specimen. 

`./pal exec` - chose lunar_landing.game then [B] to publish & run. 


```
PROJECT  lunar_lander.game
  workspace=CURRENT  publication=COMPLETE  run=READY  ABI=READY
  functions=30/30  published=30  size=8.29MiB  warnings=0
  [P] Publish  [R] Run  [T] Trace  [B] Publish+Run  [D] Details  [C] Change  [Q] Quit
Action: p

+--------------------------------------------------------------------------------------+
| [OK] PUBLISH COMPLETE                                                                |
+--------------------------------------------------------------------------------------+
| PROJECT :     lunar_lander.game                                                      |
| WORKSPACE :   /home/rem/gh/PAL/pyghidra-PAL/PAL/project/lunar_lander.game/execute    |
| CLASS / RUN : COMPLETE / READY                                                       |
| FUNCTIONS :   30 published / 0 trunks                                                |
| ABI :         30/52 plans  11/0 linked/unresolved                                    |
| ABI I/C/W :   0/0/0                                                                  |
| STRINGS :     110+0=110  unresolved PTRSUB=0                                         |
| DETAILS :     /home/rem/gh/PAL/pyghidra-PAL/PAL/project/lunar_lander.game/execute/~  |
+--------------------------------------------------------------------------------------+
Closed external shims: 15 (see /home/rem/gh/PAL/pyghidra-PAL/PAL/project/lunar_lander.game/execute/config.exec.json)

PROJECT  lunar_lander.game
  workspace=CURRENT  publication=COMPLETE  run=READY  ABI=READY
  functions=30/30  published=30  size=8.29MiB  warnings=0
  [P] Publish  [R] Run  [T] Trace  [B] Publish+Run  [D] Details  [C] Change  [Q] Quit
Action: r

+======================================================================================+
| PUBLISHED FUNCTIONS                                                                  |
| lunar_lander.game // SELECT EXECUTION ENTRY                                          |
+======================================================================================+
+----+------------------------+----------+---------------+------+
|  # | FUNCTION               | ENTRY    | MODE          | NOTE |
+----+------------------------+----------+---------------+------+
|  1 | main                   | 0x1016f0 | abi_context   | -    |
|  2 | _start                 | 0x101070 | abi_context   | -    |
|  3 | _init                  | 0x101000 | abi_context   | -    |
|  4 | FUN_00101020           | 0x101020 | abi_context   | -    |
|  5 | deregister_tm_clones   | 0x1010a0 | legacy_direct | -    |
|  6 | register_tm_clones     | 0x1010d0 | legacy_direct | -    |
|  7 | __do_global_dtors_aux  | 0x101110 | abi_context   | -    |
|  8 | initialize_lander      | 0x101159 | legacy_direct | -    |
|  9 | craft_row_for_altitude | 0x1011b0 | legacy_direct | -    |
| 10 | print_sky_row          | 0x101219 | abi_context   | -    |
| 11 | draw_lander            | 0x101252 | abi_context   | -    |
| 12 | parse_burn             | 0x1013bf | legacy_direct | -    |
| 13 | read_burn              | 0x101437 | abi_context   | -    |
| 14 | apply_burn             | 0x1014a6 | legacy_direct | -    |
| 15 | print_result           | 0x101596 | abi_context   | -    |
| 16 | lander_exit_code       | 0x1016bd | legacy_direct | -    |
| 17 | _fini                  | 0x101784 | legacy_direct | -    |
+----+------------------------+----------+---------------+------+
Function [Enter=main]: 
Fixed args, comma separated [none]: 
Variadic args, comma separated [none]: 

RUN  project=lunar_lander.game  function=function:0x1016f0  gate=READY  trace=False
PAL EXEC BUILD: pal_exec_interface_v1u_exact_integral_subregister_projection
========================================================
              PAL ASCII LUNAR LANDER
        integer physics / deterministic moon
========================================================
TURN: 0  ALTITUDE: 24  VELOCITY: 0  FUEL: 30
--------------------------------------------------------
                            
                         /A\
                            
                            
                            
                            
                            
                            
________________________________________________________
    .       *       .      MOON BASE PAL      .
--------------------------------------------------------
DESCENT RATE: SAFE BAND
Enter thrust 0..9. Gravity adds 2 each turn.
Q abandons the mission.
THRUST>

```
