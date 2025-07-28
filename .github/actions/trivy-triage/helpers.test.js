const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const {detectDiscussionLabels} = require('./helpers.js');

const configDiscussionLabels = {
  "Container Image":"ContainerImageLabel",
  "Filesystem":"FilesystemLabel",
  "Vulnerability":"VulnerabilityLabel",
  "Misconfiguration":"MisconfigurationLabel",
};

describe('trivy-triage', async function() {
  describe('detectDiscussionLabels', async function() {
    it('detect scanner label', async function() {
      const discussion = {
        body: 'hello hello\nbla bla.\n### Scanner\n\nVulnerability\n### Target\n\nContainer Image\nbye bye.', 
        category: {
          name: 'Ideas'
        }
      };
      const labels = detectDiscussionLabels(discussion, configDiscussionLabels);
      assert(labels.includes('VulnerabilityLabel'));
    });
    it('detect target label', async function() {
      const discussion = {
        body: 'hello hello\nbla bla.\n### Scanner\n\nVulnerability\n### Target\n\nContainer Image\nbye bye.', 
        category: {
          name: 'Ideas'
        }
      };
      const labels = detectDiscussionLabels(discussion, configDiscussionLabels);
      assert(labels.includes('ContainerImageLabel'));
    });
    it('detect label when it is first', async function() {
      const discussion = {
        body: '### Scanner\n\nVulnerability\n### Target\n\nContainer Image\nbye bye.', 
        category: {
          name: 'Ideas'
        }
      };
      const labels = detectDiscussionLabels(discussion, configDiscussionLabels);
      assert(labels.includes('ContainerImageLabel'));
    });
    it('detect label when it is last', async function() {
      const discussion = {
        body: '### Scanner\n\nVulnerability\n### Target\n\nContainer Image', 
        category: {
          name: 'Ideas'
        }
      };
      const labels = detectDiscussionLabels(discussion, configDiscussionLabels);
      assert(labels.includes('ContainerImageLabel'));
    });
    it('detect scanner and target labels', async function() {
      const discussion = {
        body: 'hello hello\nbla bla.\n### Scanner\n\nVulnerability\n### Target\n\nContainer Image\nbye bye.', 
        category: {
          name: 'Ideas'
        }
      };
      const labels = detectDiscussionLabels(discussion, configDiscussionLabels);
      assert(labels.includes('ContainerImageLabel'));
      assert(labels.includes('VulnerabilityLabel'));
    });
    it('detect scanner and target labels on windows', async function() {
      const discussion = {
        body: 'hello hello\r\nbla bla.\r\n### Scanner\r\n\r\nVulnerability\r\n### Target\r\n\r\nContainer Image\r\nbye bye.',
        category: {
          name: 'Ideas'
        }
      };
      const labels = detectDiscussionLabels(discussion, configDiscussionLabels);
      assert(labels.includes('ContainerImageLabel'));
      assert(labels.includes('VulnerabilityLabel'));
    });
    it('not detect other labels', async function() {
      const discussion = {
        body: 'hello hello\nbla bla.\n### Scanner\n\nVulnerability\n### Target\n\nContainer Image\nbye bye.', 
        category: {
          name: 'Ideas'
        }
      };
      const labels = detectDiscussionLabels(discussion, configDiscussionLabels);
      assert(!labels.includes('FilesystemLabel'));
      assert(!labels.includes('MisconfigurationLabel'));
    });
    it('ignores unmatched label values from body', async function() {
      const discussion = {
        body: '### Target\r\n\r\nNone\r\n\r\n### Scanner\r\n\r\nMisconfiguration', 
        category: {
          name: 'Ideas'
        }
      };
      const labels = detectDiscussionLabels(discussion, configDiscussionLabels);
      assert.deepStrictEqual(labels, ['MisconfigurationLabel']);
    });
    it('process only relevant categories', async function() {
      const discussion = {
        body: 'hello world', 
        category: {
          name: 'Announcements'
        }
      };
      const labels = detectDiscussionLabels(discussion, configDiscussionLabels);
      assert(labels.length === 0);
    });
  });
});
