#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ ! -s "$1" ]; then
  echo "用法：scripts/check-coverage.sh <coverage.json>" >&2
  exit 2
fi

jq -er '
  .data[0] as $coverage
  | def file_percent($suffix; $metric):
      ([
        $coverage.files[]
        | select(.filename | endswith($suffix))
        | .summary[$metric].percent
      ][0] // error("覆盖率报告缺少 " + $suffix));
  def require($name; $actual; $minimum):
      if $actual >= $minimum then
        {name: $name, actual: $actual, minimum: $minimum}
      else
        error($name + " 覆盖率 " + ($actual | tostring)
          + "% 低于门槛 " + ($minimum | tostring) + "%")
      end;
  [
    require("全部行"; $coverage.totals.lines.percent; 75),
    require("全部函数"; $coverage.totals.functions.percent; 65),
    require("全部区域"; $coverage.totals.regions.percent; 72),
    require("词法器行"; file_percent("/src/lexer.rs"; "lines"); 90),
    require("解析器行"; file_percent("/src/parser.rs"; "lines"); 90),
    require("格式化器行"; file_percent("/src/formatter.rs"; "lines"); 60),
    require("字节码行"; file_percent("/src/bytecode.rs"; "lines"); 88),
    require("应用归档行"; file_percent("/src/application.rs"; "lines"); 75),
    require("解释器行"; file_percent("/src/interpreter.rs"; "lines"); 77),
    require("虚拟机行"; file_percent("/src/vm.rs"; "lines"); 68),
    require("工程协议行"; file_percent("/src/engineering.rs"; "lines"); 30),
    require("包核心行"; file_percent("/crates/yanxu-package/src/package.rs"; "lines"); 70),
    require("包归档行"; file_percent("/crates/yanxu-package/src/package/archive.rs"; "lines"); 50)
  ]
  | .[]
  | "\(.name)：\(.actual)%（门槛 \(.minimum)%）"
' "$1"
