globalThis.stellaAllErrors = [];

export function StellaError(startLine, startCol, endLine, endCol, message, severity, category) {
  this.start = {
    line: startLine,
    col: startCol,
  },
    this.end = {
      line: endLine,
      col: endCol,
    },
    this.message = message;
  this.severity = "NONE";
  this.category = "SAFETY";
  this.fixes = [];
  this.addFix = function (fix) {
    this.fixes.push(fix);
    return this;
  }
}

export function StellaConsole(startLine, startCol, endLine, endCol, message, severity, category) {
  this.lines = [];
  this.log = function (message) {
    if (Array.isArray(message) || typeof message === "object") {
      this.lines.push(JSON.stringify(message));
      return;
    }

    this.lines.push("" + message);
  }
}

globalThis.console = new StellaConsole();

export function StellaFix(message, edits) {
  this.description = message;
  this.edits = edits;
}

export function StellaEdit(start, end, editType, content) {
  this.start = start;
  this.end = end;
  this.editType = editType;
  this.content = content;
}

export function buildError(startLine, startCol, endLine, endCol, message, severity, category) {
  return new StellaError(startLine, startCol, endLine, endCol, message, severity, category);
}

export function buildFix(message, list) {
  return new StellaFix(message, list);
}

export function buildEditUpdate(startLine, startCol, endLine, endCol, content) {
  return new buildEdit(startLine, startCol, endLine, endCol, "UPDATE", content);
}

export function buildEditRemove(startLine, startCol, endLine, endCol) {
  return new buildEdit(startLine, startCol, endLine, endCol, "REMOVE");
}


export function buildEditAdd(startLine, startCol, content) {
  return new buildEdit(startLine, startCol, null, null, "ADD", content);
}


export function buildEdit(startLine, startCol, endLine, endCol, editType, content) {
  const start = {
    line: startLine,
    col: startCol,
  };

  let end = {
    line: endLine,
    col: endCol,
  };

  if (!endLine || !endCol) {
    end = null;
  }
  return new StellaEdit(start, end, editType.toUpperCase(), content);
}

export function addError(error) {
  stellaAllErrors.push(error);
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
export function getCodeForNode(node, code) {
  return getCode(node.start, node.end, code);
}

// We re-use the same v8 isolate across multiple rule executions. Because the user's JavaScript can mutate variables
// external to its scope, this function allows us to ensure that a closure is executed in a "clean", non-mutated context.
export function _cleanExecute(closure) {
  stellaAllErrors.length = 0;
  console.lines.length = 0
  return closure();
}