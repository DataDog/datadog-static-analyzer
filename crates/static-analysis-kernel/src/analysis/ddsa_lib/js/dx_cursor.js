export class DxCursor {
    constructor(node) {
        /** @type {TreeSitterNode | TreeSitterFieldChildNode} */
        this._node = node;
        /** @type {DxCursor | null | undefined} */
        this._parent = undefined;
        /** @type {Array<DxCursor> | undefined} */
        this._siblings = undefined;
        /** @type {number | undefined} */
        this._mySiblingIndex = undefined;
        /** @type {Array<DxCursor> | undefined} */
        this._children = undefined;
    }

    /**
     * Returns a cursor that points to the given node.
     * @param {TreeSitterNode | TreeSitterFieldChildNode | DxCursor} node
     * @returns {DxCursor}
     */
    static from(node) {
        if (node instanceof DxCursor) return node;
        return new DxCursor(node);
    }

    /**
     * The TreeSitterNode object.
     * @type {TreeSitterNode | TreeSitterFieldChildNode}
     */
    get node() {
        return this._node;
    }

    /**
     * The node's numeric id.
     * @type {number}
     */
    get id() {
        return this._node.id;
    }

    /**
     * The node's type.
     * @returns {string}
     */
    get cstType() {
        return this._node.cstType;
    }

    /**
     * The node's field name.
     * @returns {string|undefined}
     */
    get fieldName() {
        return this._node.fieldName;
    }

    /**
     * The node's text content.
     * @returns {string}
     */
    get text() {
        return this._node.text;
    }

    /**
     * The node's start position in the source code.
     * @returns {Position}
     */
    get start() {
        return this._node.start;
    }

    /**
     * The node's end position in the source code.
     * @returns {Position}
     */
    get end() {
        return this._node.end;
    }

    /**
     * Returns this node's parent, or undefined if this node is the root node.
     * @returns {undefined|DxCursor}
     */
    parent() {
        if (this._parent === undefined) {
            let parent = globalThis.ddsa.getParent(this._node);
            if (parent === undefined) {
                this._parent = null;
            } else {
                this._parent = new DxCursor(parent);
            }
        }
        if (this._parent === null) return undefined;
        return this._parent;
    }

    /**
     * Returns the parse tree's root node.
     * @returns {DxCursor}
     */
    root() {
        let node = this;
        let parent = node.parent();
        while (parent !== undefined) {
            node = parent;
            parent = node.parent();
        }
        return node;
    }

    /**
     * Returns an array of this node's children, or an empty array if the node has no children.
     * @returns {Array<DxCursor>}
     */
    children() {
        if (this._children === undefined) {
            let children = [];
            let childNodes = globalThis.ddsa.getChildren(this._node);
            for (let i in childNodes) {
                let c = new DxCursor(childNodes[i]);
                c._parent = this;
                c._siblings = children;
                c._mySiblingIndex = Number(i);
                children.push(c);
            }
            this._children = children;
        }
        return [...this._children];
    }

    /**
     * Returns this node's first child.
     * @returns {undefined|DxCursor}
     */
    firstChild() {
        let children = this.children();
        if (children.length === 0) return undefined;
        return children[0];
    }

    /**
     * Returns this node's last child.
     * @returns {undefined|DxCursor}
     */
    lastChild() {
        let children = this.children();
        if (children.length === 0) return undefined;
        return children[children.length - 1];
    }

    /**
     * Returns an array of this node's siblings, including this node.
     * @returns {Array<DxCursor>}
     */
    siblings() {
        if (this._siblings === undefined) {
            let parent = this.parent();
            if (parent === undefined) {
                this._siblings = [];
                this._mySiblingIndex = 0;
            } else {
                let children = parent.children();
                let cld = children.find((n) => n._node.id === this._node.id);
                this._siblings = cld._siblings;
                this._mySiblingIndex = cld._mySiblingIndex;
            }
        }
        return [...this._siblings];
    }

    /**
     * Returns this node's previous sibling.
     * @returns {undefined|DxCursor}
     */
    prevSibling() {
        let siblings = this.siblings();
        if (this._mySiblingIndex === 0) return undefined;
        return siblings[this._mySiblingIndex - 1];
    }

    /**
     * Returns this node's next sibling.
     * @returns {undefined|DxCursor}
     */
    nextSibling() {
        let siblings = this.siblings();
        if (this._mySiblingIndex === siblings.length - 1) return undefined;
        return siblings[this._mySiblingIndex + 1];
    }

    /**
     * Iterates through this node's ancestors (the node's parent, then its parent, and so on.)
     * @returns {Generator<DxCursor, void, *>}
     */
    * ancestors() {
        let parent = this.parent();
        while (parent !== undefined) {
            yield parent;
            parent = parent.parent();
        }
    }

    /**
     * Iterates through this node's descendants, in depth-first order (the node's first child and its descendants,
     * then the second child and its descendants, etc.)
     * If a `pruneBranch` function is specified and returns true for a given node, the iterator
     * won't go into the node's descendants.
     * @param {undefined | function(DxCursor): boolean} pruneBranch
     */
    * descendants(pruneBranch) {
        let stk = this.children();
        while (stk.length > 0) {
            let n = stk.shift();
            yield n;
            if (!pruneBranch || !pruneBranch(n)) stk.unshift(...n.children());
        }
    }

    /**
     * Returns whether this node is a descendant of the given node.
     * @param {DxCursor} node
     */
    descendsFrom(node) {
        let parent = this.parent();
        while (parent !== undefined) {
            if (parent._node.id === node._node.id) return true;
            parent = parent.parent();
        }
        return false;
    }

    /**
     * Returns this node's child of which the given node is a descendant, or undefined if the node
     * is not a descendant.
     * @param {DxCursor} node
     * @return {DxCursor | undefined}
     */
    childContaining(node) {
        let parent = node.parent();
        while (parent !== undefined) {
            if (parent._node.id === this._node.id) return node;
            node = parent;
            parent = node.parent();
        }
        return undefined;
    }

    /**
     * Returns the first common ancestor of this node and the given node.
     * @param {DxCursor} node
     * @return {DxCursor}
     */
    commonAncestor(node) {
        // Make a list of each node's ancestors, starting at the root
        let myChain = [...this.ancestors()].reverse();
        let theirChain = [...node.ancestors()].reverse();
        for (let i = 0; i < myChain.length && i < theirChain.length; ++i) {
            if (myChain[i] !== theirChain[i]) return i === 0 ? undefined : myChain[i - 1];
        }
        // If we got to the end of a chain without finding a different ancestor, one of the inputs is
        return myChain.length <= theirChain.length ? this : node;
    }

    /**
     * Returns this node's predecessor.
     *
     * A node's predecessor is its previous sibling or, if there is no previous sibling, its parent.
     * @returns {undefined|DxCursor}
     */
    predecessor() {
        let pred = this.prevSibling();
        if (pred === undefined) pred = this.parent();
        return pred;
    }

    /**
     * Returns this node's successor.
     *
     * A node's successor is its next sibling or, if there is no next sibling, its parent's successor.
     * @returns {undefined|DxCursor}
     */
    successor() {
        let ref = this;
        let next = ref.nextSibling();
        while (next === undefined) {
            ref = ref.parent();
            if (ref === undefined) return undefined;
            next = ref.nextSibling();
        }
        return next;
    }

    /**
     * Returns the node contained in the field with the given name, or undefined if it doesn't exist.
     * @returns {DxCursor | undefined}
     */
    field(fieldName) {
        return this.children().find((n) => n._node.fieldName === fieldName);
    }

    /**
     * Returns the node of the given type contained in the field with the given name, or undefined if the
     * field doesn't exist or the node doesn't have the specified type.
     * @returns {DxCursor | undefined}
     */
    fieldOfType(fieldName, type) {
        return this.children().find(
            (n) => n._node.fieldName === fieldName && n._node.cstType === type
        );
    }

    /**
     * Returns an array containing the node in the field with the given name, or an empty array if it doesn't exist.
     * @returns {Array<DxCursor>}
     */
    fields(fieldName) {
        return this.children().filter((n) => n._node.fieldName === fieldName);
    }

    /**
     * Returns an array containing the node in the field with the given name and type, or an empty array if the
     * field does not exist or the node doesn't have the specified type.
     * @returns {Array<DxCursor>}
     */
    fieldsOfType(fieldName, type) {
        return this.children().filter(
            (n) => n._node.fieldName === fieldName && n._node.cstType === type
        );
    }

    /**
     * Returns an array containing the child nodes that have the specified type.
     * @returns {Array<DxCursor>}
     */
    childrenOfType(type) {
        return this.children().filter((n) => n._node.cstType === type);
    }

    toJSON() {
        return {cstType: this.cstType, start: this.start, end: this.end, text: this.text};
    }
}
