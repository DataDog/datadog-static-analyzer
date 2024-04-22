import { op_tree_node_count } from "ext:core/ops";

function treeNodeCount(nodeName) {
    return op_tree_node_count(nodeName);
}

globalThis.fromRust = { treeNodeCount };
