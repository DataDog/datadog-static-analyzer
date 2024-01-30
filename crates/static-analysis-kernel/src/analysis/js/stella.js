const stellaAllErrors = [];

function StellaError(startLine, startCol, endLine, endCol, message, severity, category) {
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

function StellaConsole(startLine, startCol, endLine, endCol, message, severity, category) {
  this.lines = [];
  this.log = function (message) {
    this.lines.push(message);
  }
}

console = new StellaConsole();

function StellaFix(message, edits) {
  this.description = message;
  this.edits = edits;
}

function StellaEdit(start, end, editType, content) {
  this.start = start;
  this.end = end;
  this.editType = editType;
  this.content = content;
}

function buildError(startLine, startCol, endLine, endCol, message, severity, category) {
  return new StellaError(startLine, startCol, endLine, endCol, message, severity, category);
}

function buildFix(message, list) {
  return new StellaFix(message, list);
}

function buildEditUpdate(startLine, startCol, endLine, endCol, content) {
  return new buildEdit(startLine, startCol, endLine, endCol, "UPDATE", content);
}

function buildEditRemove(startLine, startCol, endLine, endCol) {
  return new buildEdit(startLine, startCol, endLine, endCol, "REMOVE");
}


function buildEditAdd(startLine, startCol, content) {
  return new buildEdit(startLine, startCol, null, null, "ADD", content);
}


function buildEdit(startLine, startCol, endLine, endCol, editType, content) {
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

function addError(error) {
  stellaAllErrors.push(error);
}

// helper function getCode
function getCode(start, end, code) {
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
function getCodeForNode(node, code) {
  return getCode(node.start, node.end, code);
}
