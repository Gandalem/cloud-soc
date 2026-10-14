const test=require('node:test'),assert=require('node:assert/strict');
const {processingView}=require('../shell.js');
test('live and millions of historical records are displayed separately',()=>{
 const report={priority_normalizer:{lag_seconds:45},detector:{lag_seconds:30},lag_seconds:12000,
  realtime_coverage:{state:'observed'},historical_backlog:{state:'ok',count:3500000}};
 const view=processingView(report);
 assert.match(view.realtime,/실시간 분석: 최근 실행 확인.*45초.*30초/);
 assert.match(view.historical,/3,500,000건.*12,000초.*완료 기준/);
 assert.doesNotMatch(view.realtime,/3,500,000/);
});
test('unknown queue and malformed counters never become zero or echo secrets',()=>{
 const report={priority_normalizer:{lag_seconds:true},detector:{lag_seconds:-1},
  realtime_coverage:{state:'PRIVATE_CANARY'},historical_backlog:{state:'unavailable',count:0}};
 const view=processingView(report);
 assert.match(view.realtime,/미확인/);assert.match(view.historical,/미완료 구간 미확인/);
 assert.doesNotMatch(JSON.stringify(view),/PRIVATE_CANARY|0건/);
 assert.equal(processingView({}),null);
});
test('additional detector delay is visible independently from primary AUTH',()=>{
 const view=processingView({priority_normalizer:{lag_seconds:40},detector:{lag_seconds:30},
  additional_detector:{lag_seconds:1300},realtime_coverage:{state:'delayed'},
  historical_backlog:{state:'ok',count:0}});
 assert.match(view.realtime,/지연.*1,300초/);
 assert.match(view.historical,/0건/);
});
test('late review failure and its pending ranges remain separate from current latency',()=>{
 const view=processingView({priority_normalizer:{lag_seconds:39},detector:{lag_seconds:30},
  realtime_coverage:{state:'observed'},historical_backlog:{state:'ok',count:0},
  late_review:{state:'failed',pending_contexts:2}});
 assert.match(view.realtime,/최근 실행 확인.*39초/);
 assert.match(view.historical,/미완료 구간 0건.*재평가: 실패.*대기 범위 2개/);
});
