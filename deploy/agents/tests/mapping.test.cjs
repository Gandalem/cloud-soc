const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('host intake preserves overflow source without raising the mapping limit', () => {
  const template = JSON.parse(fs.readFileSync(path.join(__dirname, '../index-template.json'), 'utf8'));
  assert.deepEqual(template.index_patterns, ['soc-host-raw-*']);
  assert.equal(template.template.settings['index.mapping.total_fields.ignore_dynamic_beyond_limit'], true);
  assert.equal(template.template.settings['index.mapping.total_fields.limit'], undefined);
  assert.notEqual(template.template.mappings._source?.enabled, false);
  const fields = template.template.mappings.properties;
  assert.equal(fields.agent.properties.id.type, 'keyword');
  assert.equal(fields.organization.properties.id.type, 'keyword');
  assert.equal(fields['@timestamp'].type, 'date');
  assert.match(template._meta.description, /not searchable/);
});
