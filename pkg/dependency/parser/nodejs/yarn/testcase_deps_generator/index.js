const fs = require('fs')
const yarnpkg = require('@yarnpkg/lockfile')
const YAML = require('yaml')

const formatYarnV2 = (yaml) => {
    delete yaml.__metadata
    delete yaml["code@workspace:."]

    result = {}
    for (const [key, value] of Object.entries(yaml)) {
        for (const splitKey of key.split(', ')) {
            result[splitKey] = value
        }
    }

    for (const [key, value] of Object.entries(result)) {
        if (key.includes('@npm:')) {
            result[key.replace('@npm:', '@')] = value
            delete result[key]
        }
    }

    return result
}

const formatYarnV1 = (obj) => obj.object

const readLockFile = (filepath) => {
    const file = fs.readFileSync(filepath, 'utf8')
    try {
        return formatYarnV1(yarnpkg.parse(file))
    } catch (e) {
        return formatYarnV2(YAML.parse(file))
    }
}

const createResultObj = (yarnObj) => {
    result = {}
    for (const [key, value] of Object.entries(yarnObj)) {
        if (value.dependencies) {
            libId = key.split('@')[0] + '@' + value.version
            for (const [depName, depVersion] of Object.entries(value.dependencies)) {
                if (!result[libId]) {
                    result[libId] = {dependsOn: []}
                }
                depLocator = depName + '@' + depVersion
                depObj = yarnObj[depLocator]
                if (!depObj) {
                    a = 1
                }
                depId = depName + '@' + depObj.version
                if (!result[libId].dependsOn.includes(depId)) {
                    result[libId].dependsOn.push(depId)
                }
            }
        }
    }

    return result
}

const createResultString = (result) => {
    res = "[]types.Dependency{\n"
    for (const [key, value] of Object.entries(result)) {
        res += '{\nID:"' + key + '",\n'
        res += 'DependsOn: []string{\n"' + value.dependsOn.join('",\n"') + '",\n},\n},\n'
    }
    res += '}'
    return res
}

var args = process.argv.slice(2);
filePath = args[0]

lockfile = readLockFile(filePath)
resultObj = createResultObj(lockfile)
resultString = createResultString(resultObj)

console.log(resultString)

