(comment) @comment
(string) @string
(number) @number
(identifier) @variable

[
  "公" "令" "定" "置" "为" "言" "若" "则" "否则" "终"
  "当" "逐" "于" "异" "候" "法" "类" "承" "父" "协" "纳" "域" "私" "只" "静"
  "引" "作" "归" "试" "救" "抛"
] @keyword

[
  "真" "假" "空"
] @constant.builtin

[
  "加" "减" "乘" "除" "且" "或" "非" "等于" "不等于"
  "大于" "小于" "不小于" "不大于"
  "是"
] @operator

(function_declaration
  name: (identifier) @function)

(class_declaration
  (identifier) @type)

(protocol_declaration
  (identifier) @type)

(named_type) @type
