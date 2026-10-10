"""Synthetic snapshot/name model only; no real DOM, AX algorithm or browser.

These fixtures intentionally do not implement the separate runtime semantic
reversal guard. Successful name selection is never a dispatch permit.
"""
import re
import unittest

NATIVE = '리포스트 리포스트'
SNAPSHOT = '''- menu:
  - menuitem "리포스트 리포스트" [active]:
    - generic: 리포스트
    - img "리포스트"
  - menuitem "인용하기 인용하기":
    - generic: 인용하기
    - img "인용하기"
'''


def fixture_menuitems(snapshot):
    """Extract names in one synthetic top-level menu, not Playwright semantics."""
    lines = snapshot.splitlines()
    roots = [i for i, line in enumerate(lines) if line == '- menu:']
    if len(roots) != 1:
        raise ValueError('Exactly one synthetic menu required')
    names = []
    for line in lines[roots[0] + 1:]:
        if line.startswith('- '):
            break
        match = re.fullmatch(r'  - menuitem "([^"]+)"(?: \[[^]]+\])?:?', line)
        if match:
            names.append(match.group(1))
    return names


def unique_native_name(names, observed_name):
    """Only exact observed-name/count selection; not a semantic safety guard."""
    exact = [name for name in names if name == observed_name]
    if len(exact) != 1:
        raise ValueError('Missing or ambiguous exact choice')
    return exact[0]


class SyntheticSelectorContractTests(unittest.TestCase):
    def test_full_observed_role_name_selected_without_quote(self):
        names = fixture_menuitems(SNAPSHOT)
        self.assertEqual(names, [NATIVE, '인용하기 인용하기'])
        self.assertEqual(unique_native_name(names, NATIVE), NATIVE)

    def test_shorter_name_does_not_match_complete_observed_name(self):
        with self.assertRaises(ValueError):
            unique_native_name(fixture_menuitems(SNAPSHOT), '리포스트')

    def test_missing_quote_and_reversal_only_choices_are_not_native(self):
        for names in ([], ['인용하기 인용하기'], ['리포스트 삭제', '리포스트 취소']):
            with self.subTest(names=names), self.assertRaises(ValueError):
                unique_native_name(names, NATIVE)

    def test_duplicate_exact_candidates_fail_closed(self):
        with self.assertRaises(ValueError):
            unique_native_name([NATIVE, NATIVE], NATIVE)

    def test_missing_or_duplicate_menu_fixture_rejected(self):
        for snapshot in ('', SNAPSHOT + '\n- menu:\n'):
            with self.subTest(snapshot=snapshot), self.assertRaises(ValueError):
                fixture_menuitems(snapshot)

    def test_button_and_outside_menu_are_not_menuitem_fixture_candidates(self):
        snapshot = '- button "리포스트 리포스트":\n- menu:\n  - button "리포스트 리포스트":\n- menuitem "리포스트 리포스트":\n'
        self.assertEqual(fixture_menuitems(snapshot), [])

    def test_one_visible_global_text_match_still_has_three_total_matches(self):
        matches = [('title', False), ('span', True), ('title', False)]
        self.assertEqual(sum(visible for _, visible in matches), 1)
        self.assertEqual(len(matches), 3)
        self.assertNotEqual(len(matches), 1)

    def test_name_selection_alone_does_not_enforce_reversal_guard(self):
        # A real caller MUST separately reject this reversal state. This narrow
        # name model cannot prove that safety property and must not claim it does.
        names = [NATIVE, '리포스트 삭제', '리포스트 취소']
        self.assertEqual(unique_native_name(names, NATIVE), NATIVE)


if __name__ == '__main__':
    unittest.main()
