import {Edit} from "ext:ddsa_lib/edit";
import {Fix} from "ext:ddsa_lib/fix";
import {Violation} from "ext:ddsa_lib/violation";

export function buildError(startLine, startCol, endLine, endCol, message, severity, category) {
  return Violation.new(startLine, startCol, endLine, endCol, message);
}

export function buildFix(message, list) {
  return Fix.new(message, list);
}

export function buildEditUpdate(startLine, startCol, endLine, endCol, content) {
  return Edit.newUpdate(startLine, startCol, endLine, endCol, content);
}

export function buildEditRemove(startLine, startCol, endLine, endCol) {
  return Edit.newRemove(startLine, startCol, endLine, endCol);
}


export function buildEditAdd(startLine, startCol, content) {
  return Edit.newAdd(startLine, startCol, content);
}

export function buildEdit(startLine, startCol, endLine, endCol, editType, content) {
  return new Edit(startLine, startCol, endLine, endCol, editType.toUpperCase(), content);
}

export function addError(error) {
  globalThis.__RUST_BRIDGE__violation.push(error);
}

// helper function getCode
export function getCode(start, end, code) {
  const lines = code.split("\n");
  const startLine = start.line - 1;
  const startCol = start.col - 1;
  const endLine = end.line - 1;
  const endCol = end.col - 1;

  var startChar = 0;
  for (var i = 0; i < startLine; i++) {
    startChar = startChar + lines[i].length + 1;
  }
  startChar = startChar + startCol;

  var endChar = 0;
  for (var i = 0; i < endLine; i++) {
    endChar = endChar + lines[i].length + 1;
  }
  endChar = endChar + endCol;

  return code.substring(startChar, endChar);
};

// helper function getCodeForNode
export function getCodeForNode(node, _code) {
  return node.text;
}

/**
 * An object that, when accessed, lazily fetches the filename from the DDSA runtime context.
 * @augments String
 * @deprecated
 */
export class VisitArgFilenameCompat {
  constructor() {
    return new Proxy({ inner: undefined }, {
      get(target, p, _receiver) {
        // The RootContext maintains a cache, so we can re-assign the getter's return value each time without allocating.
        target.inner = globalThis.__RUST_BRIDGE__context.filename;

        const propValue = target.inner[p];
        if (typeof propValue === "function") {
          return propValue.bind(target.inner);
        }
        return propValue;
      },
    });
  }
}

/**
 * An object that, when accessed, lazily fetches the file contents from the DDSA runtime context.
 * @augments String
 * @deprecated
 */
export class VisitArgCodeCompat {
  constructor() {
    return new Proxy({ inner: undefined }, {
      get(target, p, _receiver) {
        // The RootContext maintains a cache, so we can re-assign the getter's return value each time without allocating.
        target.inner = globalThis.__RUST_BRIDGE__context.fileContents;

        const propValue = target.inner[p];
        if (typeof propValue === "function") {
          return propValue.bind(target.inner);
        }
        return propValue;
      },
    });
  }
}
