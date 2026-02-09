The generator tool can be tested with some tools disabled for ablation studies.


| All tools             | `--mask` value                             |
|:---|:---|
| w/o source code       | `argot_show_src` |
| w/o SSA form          | `argot_show_ssa` |
| w/o aliasing info     | `argot_show_ssa_value,argot_show_ssa_instr` |
| w/o soundness checker | `argot_dataflow_check` |

