#!/usr/bin/env node

const FS   = require("fs");
const Util = require("util");

const KdbxWeb    = require("kdbxweb");
const KdbxEntry  = require("kdbxweb/lib/format/kdbx-entry");
const Rofix      = require("rofix");
const Clipboardy = require("clipboardy");

const readFile = Util.promisify(FS.readFile);

/**
 * Exit codes for this script.
 *
 * @type {Object}
 */
const EXIT_CODE = {
    OK:        0,
    BAD_USAGE: 1
};

/**
 * @description
 * Validates passed arguments.
 * In case of issues, sets `help` flag.
 *
 * @param {Object} parsedArgs - Arguments to be checked.
 */
function validateArgs(parsedArgs) {
    if (!parsedArgs.filename
    ||  !parsedArgs.password) {
        parsedArgs.help = true;
    }
}

/**
 * @description
 * Parses command line arguments.
 *
 * @returns {Object}
 */
function parseArgs() {
    const cliArgs    = process.argv.slice(2);
    const parsedArgs = {
        filename: null,
        password: null,
        all:      false,
        help:     false
    };

    for (let i = 0; i < cliArgs.length; ++i) {
        const arg = cliArgs[i];

        switch (arg) {
            case "-f":
            case "--filename":
                parsedArgs.filename = cliArgs[++i];
                break;

            case "-p":
            case "--password":
                parsedArgs.password = cliArgs[++i];
                break;

            case "-a":
            case "--all":
                parsedArgs.all = true;
                break;

            case "-?":
            case "-h":
            case "--help":
            default:
                parsedArgs.help = true;
                break;
        }
    }

    validateArgs(parsedArgs);

    return parsedArgs;
}

/**
 * @description
 * Displays help message.
 */
function showHelp() {
    console.log("keepass-rofi usage:");
    console.log("\tkeepass-rofi -f|--filename <keepass-db-filename> -p|--password <password> [-a|--all]");
    console.log("\tkeepass-rofi [-?|-h|--help]");
}

/**
 * @description
 * Reads the KeePass file.
 *
 * @param   {String} filename - Path to the KeePass file.
 *
 * @returns {ArrayBuffer}     - Buffer with read data.
 */
async function readDbFile(filename) {
    const contents = await readFile(filename);

    return contents.buffer;
}

/**
 * @description
 * Opens KeePass database file.
 *
 * @param {String} filename - Path to the KeePass file.
 * @param {String} password - Password for the file.
 */
async function openDbFile(filename, password) {
    const dbFile      = await readDbFile(filename);
    const credentials = new KdbxWeb.Credentials(KdbxWeb.ProtectedValue.fromString(password));

    return await KdbxWeb.Kdbx.load(dbFile, credentials);
}

/**
 * @description
 * Entry point.
 */
async function main() {
    const args = parseArgs();

    if (args.help) {
        showHelp();
        process.exit(EXIT_CODE.BAD_USAGE);
    }

    try {
        let db = await openDbFile(args.filename, args.password);

        if (args.all) {
            db = {
                entries: getAllEntriesFlat(db)
            };
        }

        const entry = await selectEntry(db);

        await Clipboardy.write(entry.fields.Password.getText());
    } catch (error) {
        console.error(error);
    }

    process.exit(EXIT_CODE.OK);
}

/**
 * @description
 * Gets all nested entries from all groups.
 *
 * @param   {KdbxWeb.Kdbx|KdbxGroup} group - KeePass database of group of entries.
 *
 * @returns {Array<KdbxEntry>}
 */
function getAllEntriesFlat(group) {
    const nested = group.groups.map(getAllEntriesFlat).flat();

    return (group.entries || []).concat(nested);
}

/**
 * @description
 * Uses Rofi to query user for an entry.
 *
 * @param   {KdbxWeb.Kdbx|KdbxGroup} group - KeePass database of group of entries.
 *
 * @returns {KdbxEntry}
 */
async function selectEntry(group) {
    const result = await getRofiSelection(group);

    if (result instanceof KdbxEntry) {
        return result;
    }

    return selectEntry(result);
}

/**
 * @description
 * Obtains all entries from a group.
 *
 * @param   {KdbxWeb.Kdbx|KdbxGroup} group - KeePass database of group of entries.
 *
 * @returns {Array<String>}
 */
function getEntriesNames(group) {
    return (group.entries || []).map((entry) => {
        return `Entry: ${entry.fields.Title}`;
    });
}

/**
 * @description
 * Obtains all nested groups from a group.
 *
 * @param   {KdbxWeb.Kdbx|KdbxGroup} group - KeePass database of group of entries.
 *
 * @returns {Array<String>}
 */
function getGroupsNames(group) {
    return (group.groups || []).map((group) => {
        return `Group: ${group.name}`;
    });
}

/**
 * @description
 * Calls Rofi to get user's selection.
 *
 * @param   {KdbxWeb.Kdbx|KdbxGroup} group - KeePass database of group of entries.
 *
 * @returns {KdbxGroup|KdbxEntry}  - Selected item.
 */
async function getRofiSelection(group) {
    const entries   = getEntriesNames(group);
    const groups    = getGroupsNames(group);
    const menu      = new Rofix.Menu(entries.concat(groups));
    const selection = JSON.parse(await menu.open());

    if (selection.code || !selection.stdout) {
        return null; // User canceled
    }

    const pattern       = new RegExp(/^(Entry|Group): (.*)$/);
    const [type, value] = pattern.exec(selection.stdout).slice(1);

    if (type === "Entry") {
        return group.entries.find((entry) => {
            return entry.fields.Title === value;
        });
    }

    // Otherwise, we have a "Group"
    return group.groups.find((group) => {
        return group.name === value;
    });
}

main();
