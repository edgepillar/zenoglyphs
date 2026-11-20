import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {createHash} from 'node:crypto'
import {lstatSync, readFileSync, readdirSync, writeFileSync} from 'node:fs'
import {join, resolve} from 'node:path'
import {fileURLToPath} from 'node:url'

const ui = fileURLToPath(new URL('../', import.meta.url))
const repo = resolve(ui, '../..')
const nomUi = {
  commit: '63f755a52cf6ee3665d3755755c506e3aa191bd4',
  sourceTree: '38e44fcd5bc4d8fd0c499448ab3cd834391c30b2',
  manifestSha256: '09218d2bde5fa311cd3ad1b9d2427a6f845ff9d32b9a196662357b36c20347c0',
  licenseSha256: '683675e786f49e060467fcfcb7796b4d663d16c0de92997ed8a3c0711ccd026d',
}
const nomUiLocation = 'node_modules/nom-ui'
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

function gitObject(type, bytes) {
  return createHash('sha1').update(type + ' ' + bytes.length + '\0').update(bytes).digest()
}

function git(...args) {
  return execFileSync('git', args, {cwd: repo, encoding: 'utf8', timeout: 10000}).trim()
}

function trackedFile(path) {
  const bytes = readFileSync(join(repo, path))
  assert.equal(gitObject('blob', bytes).toString('hex'), git('rev-parse', '--verify', 'HEAD:' + path),
    'Tracked viewer build input differs')
  return bytes
}

function lockInputs() {
  const manifest = trackedFile('web/ui/package.json')
  const lock = trackedFile('web/ui/package-lock.json')
  const root = JSON.parse(manifest)
  const selected = JSON.parse(lock)
  assert.equal(selected.lockfileVersion, 3, 'Expected an npm v3 lock')
  assert.deepEqual(selected.packages[''].dependencies, root.dependencies, 'Runtime dependency declarations differ')
  assert.deepEqual(selected.packages[''].devDependencies, root.devDependencies, 'Build dependency declarations differ')
  assert.equal(root.dependencies['nom-ui'], 'github:digitalSloth/nom-ui', 'Git dependency declaration differs')
  assert.equal(selected.packages[nomUiLocation].resolved, 'git+ssh://git@github.com/digitalSloth/nom-ui.git#' + nomUi.commit,
    'Review the new nom-ui source before qualifying this lock')
  let registryLocations = 0
  for (const [location, row] of Object.entries(selected.packages)) {
    if (!location || location === nomUiLocation) continue
    const name = row.name ?? location.split('node_modules/').at(-1)
    const expected = 'https://registry.npmjs.org/' + name + '/-/' + name.split('/').at(-1) + '-' + row.version + '.tgz'
    assert.match(location, /^node_modules\/(?:[A-Za-z0-9_@.-]+\/)*[A-Za-z0-9_.-]+$/, 'Invalid lock location')
    assert(location.split('/').every(part => part !== '.' && part !== '..'), 'Invalid lock directory')
    assert.match(name, /^(?:@[A-Za-z0-9_.-]+\/)?[A-Za-z0-9_.-]+$/, 'Invalid registry package name')
    assert.match(row.integrity ?? '', /^sha512-[A-Za-z0-9+/]{86}==$/, 'Registry integrity differs')
    assert.equal(row.resolved, expected, 'Registry archive URL differs')
    assert(!row.link, 'Unexpected linked dependency')
    registryLocations++
  }
  return {manifestSha256: sha256(manifest), lockSha256: sha256(lock), registryLocations, nomUi}
}

function inventory(root) {
  const files = Object.create(null)
  let fileCount = 0
  let totalBytes = 0
  let entries = 0
  function directory(current, relative) {
    assert(lstatSync(current).isDirectory() && relative.length <= 512, 'Invalid viewer evidence directory')
    const records = []
    for (const item of readdirSync(current, {withFileTypes: true})) {
      assert(++entries <= 3000 && /^[A-Za-z0-9_.@+-]+$/.test(item.name), 'Viewer inventory entry limit or name')
      const path = join(current, item.name)
      const name = relative + item.name
      const info = lstatSync(path)
      if (info.isDirectory()) {
        records.push({name: item.name, sortKey: item.name + '/', mode: '40000', digest: directory(path, name + '/')})
        continue
      }
      assert(info.isFile() && info.size <= 4 << 20, 'Viewer evidence requires a bounded regular file')
      totalBytes += info.size
      assert(++fileCount <= 1024 && totalBytes <= 24 << 20, 'Viewer inventory limit')
      const body = readFileSync(path)
      assert.equal(body.length, info.size, 'Viewer file size changed during inspection')
      const mode = info.mode & 0o111 ? '100755' : '100644'
      files[name] = {bytes: body.length, sha256: sha256(body), mode}
      records.push({name: item.name, sortKey: item.name, mode, digest: gitObject('blob', body)})
    }
    records.sort((left, right) => left.sortKey < right.sortKey ? -1 : left.sortKey > right.sortKey ? 1 : 0)
    return gitObject('tree', Buffer.concat(records.flatMap(row => [
      Buffer.from(row.mode + ' ' + row.name + '\0'),
      row.digest,
    ])))
  }
  const gitTree = directory(root, '').toString('hex')
  return {fileCount, totalBytes, gitTree, files: Object.fromEntries(Object.entries(files).sort())}
}

function installedGitSource() {
  const source = join(ui, nomUiLocation)
  assert(lstatSync(source).isDirectory(), 'Expected a regular installed Git package directory')
  assert(lstatSync(join(source, 'package.json')).isFile() && lstatSync(join(source, 'LICENSE')).isFile(),
    'Expected regular Git package manifest and license files')
  assert.equal(sha256(readFileSync(join(source, 'package.json'))), nomUi.manifestSha256, 'Installed nom-ui manifest differs')
  assert.equal(sha256(readFileSync(join(source, 'LICENSE'))), nomUi.licenseSha256, 'Installed nom-ui license differs')
  const sourceFiles = inventory(join(source, 'src'))
  assert.equal(sourceFiles.gitTree, nomUi.sourceTree, 'Installed nom-ui source tree differs from the locked Git commit')
  return {sourceFiles: sourceFiles.fileCount, sourceBytes: sourceFiles.totalBytes, ...nomUi}
}

function compare(rebuiltPath, reportPath) {
  const committed = inventory(join(repo, 'web/dist'))
  const rebuilt = inventory(resolve(rebuiltPath))
  assert.equal(committed.gitTree, git('rev-parse', '--verify', 'HEAD:web/dist'), 'Embedded files differ from the selected Git tree')
  for (const path of ['index.html', 'admin/index.html']) {
    assert(committed.files[path] && rebuilt.files[path], 'Expected both viewer entry pages')
  }
  const paths = [...new Set([...Object.keys(committed.files), ...Object.keys(rebuilt.files)])].sort()
  const added = paths.filter(path => !Object.hasOwn(committed.files, path))
  const missing = paths.filter(path => !Object.hasOwn(rebuilt.files, path))
  const changed = paths.filter(path => Object.hasOwn(committed.files, path) && Object.hasOwn(rebuilt.files, path)
    && (committed.files[path].sha256 !== rebuilt.files[path].sha256 || committed.files[path].mode !== rebuilt.files[path].mode))
  const equal = committed.gitTree === rebuilt.gitTree
  const report = {
    schema: 1,
    status: equal ? 'EMBEDDED_VIEWER_REPRODUCED' : 'EMBEDDED_VIEWER_DIFFERS',
    sourceCommit: git('rev-parse', '--verify', 'HEAD'),
    runId: process.env.GITHUB_RUN_ID ?? null,
    attempt: process.env.GITHUB_RUN_ATTEMPT ?? null,
    toolchain: {node: process.version, npm: process.env.VIEWER_NPM_VERSION ?? null, platform: process.platform, arch: process.arch},
    inputs: lockInputs(),
    committed,
    rebuilt,
    comparison: {equal, added, missing, changed, matchingFiles: paths.length - added.length - missing.length - changed.length},
  }
  const data = JSON.stringify(report, null, 2) + '\n'
  assert(Buffer.byteLength(data) <= 512 << 10, 'Viewer report exceeds its size limit')
  writeFileSync(reportPath, data, {flag: 'wx', mode: 0o600})
  console.log('### Embedded viewer rebuild\n')
  console.log('Source ' + report.sourceCommit)
  console.log('Result ' + report.status)
  console.log('npm lock SHA-256 ' + report.inputs.lockSha256)
  console.log('Committed tree ' + committed.gitTree + ' with ' + committed.fileCount + ' files.')
  console.log('Rebuilt tree ' + rebuilt.gitTree + ' with ' + rebuilt.fileCount + ' files.')
  console.log('Matching files ' + report.comparison.matchingFiles + '. Added ' + added.length + ', missing ' + missing.length
    + ', changed at the same path ' + changed.length + '.')
  if (!equal) process.exitCode = 1
}

const [mode, rebuilt, report] = process.argv.slice(2)
if (mode === 'inputs' && process.argv.length === 3) console.log(JSON.stringify(lockInputs()))
else if (mode === 'installed' && process.argv.length === 3) console.log(JSON.stringify(installedGitSource()))
else if (mode === 'compare' && rebuilt && report && process.argv.length === 5) compare(rebuilt, report)
else throw new Error('Use inputs, installed, or compare <rebuilt-directory> <new-report-file>.')
