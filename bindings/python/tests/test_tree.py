import pytest
from mrkle.tree import MrkleTree
from mrkle.crypto import Sha1


def test_empty_tree():
    tree = MrkleTree.from_leaves([])
    assert tree.is_empty()
    assert len(tree) == 0


def test_empty_dict():
    with pytest.raises(
        ValueError, match="The dictionary can not contain more than one root."
    ):
        _ = MrkleTree.from_dict({})


def test_from_single_leaf_tree():
    tree = MrkleTree.from_leaves(["hello"])
    assert len(tree) == 2


def test_from_two_leaves():
    tree = MrkleTree.from_leaves(["hello", "world"])
    assert len(tree) == 3
    assert not tree.is_empty()


def test_from_multiple_leaves():
    tree = MrkleTree.from_leaves(["a", "b", "c", "d"])
    assert len(tree) == 7  # 4 leaves + 3 internal nodes


def test_from_bytes_leaves():
    tree = MrkleTree.from_leaves([b"hello", b"world", b"test"])
    assert len(tree) == 5


# Dictionary Construction Tests
def test_from_dict_nested():
    tree = MrkleTree.from_dict({"a": {"b": "hello", "c": "world"}})
    digest = Sha1()
    digest.update(Sha1.digest(b"hello"))
    digest.update(Sha1.digest(b"world"))
    root = digest.finalize_reset()
    assert len(tree) == 3
    assert root == tree.root()
    assert [node for node in filter(lambda x: x.value(), iter(tree))] == tree.leaves()


def test_from_dict_flattened():
    tree = MrkleTree.from_dict(
        {"a.a": b"hello", "a.b": b"world", "a.c": "!"}, format="flatten"
    )
    assert len(tree) == 4


def test_from_dict_deep_nesting():
    tree = MrkleTree.from_dict({"root": {"level1": {"level2": {"leaf": "deep"}}}})
    assert len(tree) == 4


def test_from_dict_multiple_branches():
    tree = MrkleTree.from_dict(
        {"root": {"branch1": {"a": "1", "b": "2"}, "branch2": {"c": "3", "d": "4"}}}
    )
    assert len(tree) == 7


# Root and Hash Tests
def test_root_hash_consistency():
    tree1 = MrkleTree.from_leaves(["a", "b", "c"])
    tree2 = MrkleTree.from_leaves(["a", "b", "c"])
    assert tree1.root() == tree2.root()


def test_root_hash_different_order():
    tree1 = MrkleTree.from_leaves(["a", "b", "c"])
    tree2 = MrkleTree.from_leaves(["c", "b", "a"])
    assert tree1.root() != tree2.root()


def test_root_hash_single_leaf():
    tree = MrkleTree.from_leaves([b"single"])
    root = tree.root()
    assert root is not None
    assert len(root) > 0


# Leaf Access Tests
def test_leaves_retrieval():
    leaves_data = ["a", "b", "c", "d"]
    tree = MrkleTree.from_leaves(leaves_data)
    leaves = tree.leaves()
    assert len(leaves) == len(leaves_data)


def test_leaves_are_leaf_nodes():
    tree = MrkleTree.from_leaves(["x", "y", "z"])
    leaves = tree.leaves()
    for leaf in leaves:
        assert leaf.value() is not None


def test_empty_tree_no_leaves():
    tree = MrkleTree.from_leaves([])
    assert tree.leaves() == []


# Iterator Tests
def test_iteration_over_tree():
    tree = MrkleTree.from_leaves(["a", "b", "c"])
    nodes = list(iter(tree))
    assert len(nodes) == len(tree)


def test_filter_leaf_nodes():
    tree = MrkleTree.from_leaves(["a", "b", "c", "d"])
    leaf_nodes = [node for node in filter(lambda x: x.value(), iter(tree))]
    assert len(leaf_nodes) == 4


def test_filter_internal_nodes():
    tree = MrkleTree.from_leaves(["a", "b", "c", "d"])
    internal_nodes = [node for node in filter(lambda x: not x.value(), iter(tree))]
    assert len(internal_nodes) > 0


# Edge Cases
def test_single_byte_leaf():
    tree = MrkleTree.from_leaves([b"\x00"])
    assert len(tree) == 2
    assert tree.root() is not None


def test_large_leaf_count():
    leaves = [f"leaf_{i}".encode() for i in range(100)]
    tree = MrkleTree.from_leaves(leaves)
    assert len(tree.leaves()) == 100


def test_unicode_leaves():
    tree = MrkleTree.from_leaves(["Hello", "世界", "🌍"])
    assert len(tree) > 3
    assert tree.root() is not None


def test_mixed_types_leaves():
    tree = MrkleTree.from_leaves(["string", b"bytes", "unicode 文字"])
    assert len(tree) == 5


def test_empty_string_leaf():
    tree = MrkleTree.from_leaves([""])
    assert len(tree) == 2


def test_duplicate_leaves():
    tree = MrkleTree.from_leaves(["same", "same", "same"])
    assert len(tree) == 5


# Proof/Verification Tests (if applicable)
def test_tree_deterministic():
    data = ["test1", "test2", "test3", "test4"]
    tree1 = MrkleTree.from_leaves(data)
    tree2 = MrkleTree.from_leaves(data)

    assert tree1.root() == tree2.root()
    assert len(tree1) == len(tree2)


# Digest Operations
def test_digest_update_order():
    digest1 = Sha1()
    digest1.update(Sha1.digest(b"hello"))
    digest1.update(Sha1.digest(b"world"))
    result1 = digest1.finalize_reset()

    digest2 = Sha1()
    digest2.update(Sha1.digest(b"hello"))
    digest2.update(Sha1.digest(b"world"))
    result2 = digest2.finalize_reset()

    assert result1 == result2


def test_digest_different_order():
    digest1 = Sha1()
    digest1.update(Sha1.digest(b"hello"))
    digest1.update(Sha1.digest(b"world"))
    result1 = digest1.finalize_reset()

    digest2 = Sha1()
    digest2.update(Sha1.digest(b"world"))
    digest2.update(Sha1.digest(b"hello"))
    result2 = digest2.finalize_reset()

    assert result1 != result2


def test_node_has_value():
    tree = MrkleTree.from_leaves(["test"])
    leaves = tree.leaves()
    assert leaves[0].value() == b"test"


def test_internal_nodes_no_value():
    tree = MrkleTree.from_leaves(["a", "b", "c", "d"])
    all_nodes = list(iter(tree))
    leaves = tree.leaves()
    internal_nodes = [n for n in all_nodes if n not in leaves]

    for node in internal_nodes:
        assert node.value() is None


def test_trees_with_same_data_equal_roots():
    tree1 = MrkleTree.from_leaves([b"data1", b"data2", b"data3"])
    tree2 = MrkleTree.from_leaves([b"data1", b"data2", b"data3"])
    assert tree1.root() == tree2.root()


def test_trees_with_different_data_different_roots():
    tree1 = MrkleTree.from_leaves([b"data1", b"data2"])
    tree2 = MrkleTree.from_leaves([b"data3", b"data4"])
    assert tree1.root() != tree2.root()


def test_subset_different_roots():
    tree1 = MrkleTree.from_leaves([b"a", b"b", b"c"])
    tree2 = MrkleTree.from_leaves([b"a", b"b"])
    assert tree1.root() != tree2.root()


def test_from_iter_leaves():
    leaves = iter([b"a", b"b", b"c"])
    tree = MrkleTree.from_leaves(leaves)
    assert isinstance(tree, MrkleTree)


def test_tree_branch():
    leaves = iter([b"a", b"b", b"c"])
    tree = MrkleTree.from_leaves(leaves)
    leaf = tree[0]
    branch = tree.branch(tree[0])
    current = leaf
    for node in branch:
        assert current == node
        if parent := current.parent():
            current = tree[parent]


def test_tree_branch_out_of_bounds():
    with pytest.raises(IndexError) as _:
        # NOTE: out of bounds there exist only
        # 5 nodes.
        tree = MrkleTree.from_leaves(iter([b"a", b"b", b"c"]))
        _ = tree.branch(7)


def test_tree_branch_root():
    leaves = iter([b"a", b"b", b"c"])
    tree = MrkleTree.from_leaves(leaves)
    branch = tree.branch(-1)
    # NOTE: starting from the root the only node
    # to iter is the root node.
    for node in branch:
        assert tree[-1] == node
