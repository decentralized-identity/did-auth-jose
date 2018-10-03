// this is a Jasmine helper function used to export results as xunit tests results.
var jasmineReporters = require('jasmine-reporters');

var nunitReporter = new jasmineReporters.NUnitXmlReporter({
  savePath: './',
  consolidateAll: false,
});

jasmine.getEnv().addReporter(nunitReporter);