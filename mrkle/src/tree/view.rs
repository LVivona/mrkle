use super::iter::{ViewIndexIter, ViewIter};
use super::{DefaultIx, IndexType, Node, NodeIndex, Tree};
use crate::prelude::*;

/// [`TreeView`] is a view into the hierachical of [`Tree`].
///
/// It a borrowed store of a sub-tree containing nodes connected
/// in a parent-child relationship. Similarly to the [`Tree`].
#[derive(Debug)]
pub struct TreeView<'s, N: Node<Ix>, Ix: IndexType = DefaultIx> {
    /// The index of the root.
    pub(crate) root: NodeIndex<Ix>,
    /// Collection of all node spaning from the root.
    pub(crate) nodes: BTreeMap<NodeIndex<Ix>, &'s N>,
}

impl<'s, N: Node<Ix>, Ix: IndexType> TreeView<'s, N, Ix> {
    /// Create an view of the [`Tree`].
    pub(crate) fn new(root: NodeIndex<Ix>, nodes: Vec<(NodeIndex<Ix>, &'s N)>) -> Self {
        Self {
            root,
            nodes: nodes.iter().map(|(idx, node)| (*idx, *node)).collect(),
        }
    }

    /// Returns the refrence to the [`Node`].
    pub fn root(&self) -> &'s N {
        self.nodes.get(&self.root).unwrap()
    }

    /// Returns the number of nodes currently in the tree.
    #[inline]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns `true` if the tree contains no nodes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns a reference to the Node corresponding to the key.
    pub fn get(&self, index: &NodeIndex<Ix>) -> Option<&'s N> {
        if let Some(&node) = self.nodes.get(index) {
            Some(node)
        } else {
            None
        }
    }

    /// Returns Iterator pattern [`ViewIter<'s, N, Ix>`] which returns a
    /// unmutable Node reference.
    pub fn iter(self) -> ViewIter<'s, N, Ix> {
        ViewIter::new(self)
    }

    /// Returns Iterator pattern [`ViewIndexIter`] which returns a
    /// [`NodeIndex<Ix>`] of the node.
    ///
    /// # Example
    pub fn iter_idx(self) -> ViewIndexIter<'s, N, Ix> {
        ViewIndexIter::new(self)
    }
}

impl<'source, N: Node<Ix>, Ix: IndexType> From<&'source Tree<N, Ix>> for TreeView<'source, N, Ix> {
    fn from(value: &'source Tree<N, Ix>) -> Self {
        let root = value.root.unwrap();
        let root_node: &N = &value[root];
        let mut nodes: Vec<(NodeIndex<Ix>, &'source N)> = vec![(root, root_node)];
        // TODO: When iter trait is implmented use
        // to search through the tree instead
        // of hard coded BFS search through the tree.
        let mut q: VecDeque<NodeIndex<Ix>> = VecDeque::from(vec![root]);
        while let Some(idx) = q.pop_front() {
            let node = &value[idx];
            for child in node.children() {
                nodes.push((child, &value[child]));
                q.push_back(child);
            }
        }

        TreeView::new(root, nodes)
    }
}

impl<'s, N: Node<Ix>, Ix: IndexType> IntoIterator for TreeView<'s, N, Ix> {
    type IntoIter = ViewIter<'s, N, Ix>;
    type Item = &'s N;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod test {

    use crate::prelude::*;
    use crate::tree::node::DefaultNode as Node;
    use crate::{NodeIndex, Tree};

    #[test]
    fn test_tree_view_construction() {
        let mut root: Node<String> = Node::new("hello".to_string());
        root.children = vec![NodeIndex::new(1), NodeIndex::new(2)];
        let mut tree: Tree<Node<String>> = Tree::new();

        tree.root = Some(NodeIndex::new(0));
        tree.nodes.push(root);

        tree.nodes.push(Node::new("world".to_string()));
        tree.nodes.push(Node::new("!".to_string()));

        let view = tree.view();
        let node = view.root();

        assert!(node == &tree.nodes[0])
    }
}
