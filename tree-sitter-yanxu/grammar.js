module.exports = grammar({
  name: 'yanxu',

  extras: $ => [/\s/, $.comment],
  word: $ => $.identifier,

  rules: {
    source_file: $ => repeat(choice($._statement, $.public_import_statement)),

    comment: _ => token(choice(seq('#', /.*/), seq('//', /.*/))),

    _statement: $ => choice(
      $.declaration, $.function_declaration, $.class_declaration, $.protocol_declaration, $.assignment,
      $.print_statement, $.return_statement, $.import_statement, $.if_statement,
      $.while_statement, $.for_statement, $.try_statement, $.throw_statement,
      $.expression_statement
    ),

    declaration: $ => seq(optional('公'), choice('令', '定'), $.identifier,
      optional($.type_annotation), '为', $.expression, '；'),
    assignment: $ => seq('置', $.expression, '为', $.expression, '；'),
    print_statement: $ => seq('言', $.expression, '；'),
    return_statement: $ => seq('归', optional($.expression), '；'),
    import_statement: $ => seq('引', $.string, choice('为', '作'), $.identifier, '；'),
    public_import_statement: $ => seq('公', '引', $.string, choice('为', '作'), $.identifier, '；'),
    function_declaration: $ => seq(optional('公'), optional('异'), '法', field('name', $.identifier), '（',
      optional(commaSep1($.parameter)), '）', optional($.type_annotation), '则',
      repeat($._statement), '终'),
    parameter: $ => seq($.identifier, optional($.type_annotation)),
    class_declaration: $ => seq(optional('公'), '类', field('name', $.identifier),
      optional(seq('承', field('superclass', $.type_path))),
      optional(seq('纳', commaSep1(field('protocol', $.type_path)))),
      '则', repeat($.class_member), '终'),
    class_member: $ => choice($.field_declaration, $.method_declaration),
    member_modifiers: _ => repeat1(choice('公', '私', '只', '静')),
    field_declaration: $ => seq(optional($.member_modifiers), '域', field('name', $.identifier),
      $.type_annotation, optional(seq('为', $.expression)), '；'),
    method_declaration: $ => seq(optional($.member_modifiers), optional('异'), '法', field('name', $.identifier), '（',
      optional(commaSep1($.parameter)), '）', optional($.type_annotation), '则',
      repeat($._statement), '终'),
    protocol_declaration: $ => seq(optional('公'), '协', field('name', $.identifier), '则',
      repeat(choice($.protocol_field, $.protocol_method)), '终'),
    protocol_field: $ => seq('域', field('name', $.identifier), $.type_annotation, '；'),
    protocol_method: $ => seq(optional('异'), '法', field('name', $.identifier), '（',
      optional(commaSep1($.parameter)), '）', optional($.type_annotation), '；'),
    expression_statement: $ => seq($.expression, '；'),

    if_statement: $ => seq('若', $.expression, '则', repeat($._statement),
      optional(seq('否则', repeat($._statement))), '终'),
    while_statement: $ => seq('当', $.expression, '则', repeat($._statement), '终'),
    for_statement: $ => seq('逐', $.identifier, optional($.type_annotation), '于',
      $.expression, '则', repeat($._statement), '终'),
    try_statement: $ => seq('试', '则', repeat($._statement), '救', $.identifier,
      '则', repeat($._statement), '终'),
    throw_statement: $ => seq('抛', $.expression, '；'),

    type_annotation: $ => seq('：', $.type),
    type: $ => choice($.union_type, $._type_primary),
    union_type: $ => prec.left(1, seq($._type_primary, repeat1(seq('|', $._type_primary)))),
    _type_primary: $ => choice($.nullable_type, $.generic_type, $.function_type, $.named_type),
    nullable_type: $ => prec(3, seq(choice($.generic_type, $.function_type, $.named_type), '?')),
    generic_type: $ => prec(2, seq($.type_path, '<', commaSep1($.type), '>')),
    function_type: $ => prec(4, seq('法', '（', optional(commaSep1($.type)), '）', '：', $.type)),
    named_type: $ => choice($.type_path, '法', '类', '空'),
    type_path: $ => prec.right(10, seq($.identifier, repeat(seq('.', $.identifier)))),

    expression: $ => choice(
      $.identifier, $.number, $.string, '真', '假', '空', '此', $.super_expression,
      $.list, $.tuple, $.map, $.unary_expression, $.await_expression, $.binary_expression,
      $.type_test_expression, $.call_expression, $.member_expression, $.index_expression
    ),
    super_expression: $ => prec(9, seq('父', '.', $.identifier)),
    type_test_expression: $ => prec.left(3, seq($.expression, '是', $.type)),
    list: $ => seq('【', optional(commaSep($.expression)), '】'),
    tuple: $ => seq('（', commaSep1($.expression), '）'),
    map: $ => seq('{', optional(commaSep(seq($.expression, '：', $.expression))), '}'),
    unary_expression: $ => prec(7, seq(choice('非', '-'), $.expression)),
    await_expression: $ => prec(7, seq('候', $.expression)),
    binary_expression: $ => choice(
      ...[['或', 1], ['且', 2], ['等于', 3], ['不等于', 3], ['大于', 4],
        ['小于', 4], ['不小于', 4], ['不大于', 4], ['加', 5], ['减', 5],
        ['乘', 6], ['除', 6]].map(([op, level]) => prec.left(level, seq($.expression, op, $.expression)))
    ),
    call_expression: $ => prec(9, seq($.expression, '（', optional(commaSep($.expression)), '）')),
    member_expression: $ => prec(9, seq($.expression, '.', $.identifier)),
    index_expression: $ => prec(9, seq($.expression, '【', optional($.expression),
      optional(seq('：', optional($.expression))), '】')),

    identifier: _ => /[^0-9\s\(\)（）\[\]【】{},，:：.;；+\-*\/!=><|?#？「」“”][^\s\(\)（）\[\]【】{},，:：.;；+\-*\/!=><|?#？「」“”]*/,
    number: _ => /\d+(\.\d+)?/,
    string: _ => token(choice(seq('「', repeat(choice(/[^」\\]/, /\\./)), '」'),
      seq('"', repeat(choice(/[^"\\]/, /\\./)), '"')))
  }
});

function commaSep(rule) { return commaSep1(rule); }
function commaSep1(rule) { return seq(rule, repeat(seq(choice(',', '，'), rule))); }
