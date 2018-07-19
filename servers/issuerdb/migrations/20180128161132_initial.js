
exports.up = function(knex, Promise) {
  return knex.schema.createTable('tblUsedIds', (table) => {
    table.string('Id').notNull().primary();
  }).createTable('tblClients', (table) => {
    table.string('Public Key').notNull().primary();
    table.decimal('Balance', 16, 2).notNull();
  });
};

exports.down = function(knex, Promise) {
  return Promise.all([
    knex.schema.dropTable('tblUsedIds'),
    knex.schema.dropTable('tblClients'),
  ]);
};
