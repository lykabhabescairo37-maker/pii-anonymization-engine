import unittest
from engine import PIIAutomatonEngine


class TestPIIAutomatonEngine(unittest.TestCase):
    def setUp(self):
        self.engine = PIIAutomatonEngine()

    def test_32_comprehensive_cases(self):
        """
        32 test cases covering Emails, API Keys (including '@' edge cases),
        Phone Numbers, and non-PII rejection cases.
        """
        test_cases = [
            # --- Proposal Page 6 Exact Traces (1-6) ---
            ("john.doe@email.com", True, "EMAIL", "q1"),
            ("johndoe.com", False, "EMAIL", "q_d"),
            ("sk-proj-abc123xyz789def456", True, "API_KEY", "q1"),
            ("sk-short", False, "API_KEY", "q_d"),
            ("+639123456789", True, "PHONE", "q1"),
            ("abc-phone-num", False, "NONE", "q_d"),

            # --- Valid Emails (7-12) ---
            ("lykabhabescairo37@gmail.com", True, "EMAIL", "q1"),
            ("trina.eslawan@nwssu.edu.ph", True, "EMAIL", "q1"),
            ("dev_ops+alerts@company.org", True, "EMAIL", "q1"),
            ("admin123@sub.domain.net", True, "EMAIL", "q1"),
            ("user-name@my-site.io", True, "EMAIL", "q1"),
            ("a@b.co", True, "EMAIL", "q1"),

            # --- Invalid Emails (13-17) ---
            ("@missinglocal.com", False, "EMAIL", "q_d"),
            ("missingdomain@", False, "EMAIL", "q_d"),
            ("two@@emails.com", False, "EMAIL", "q_d"),
            ("badtld@domain.c", False, "EMAIL", "q_d"),
            ("numtld@domain.123", False, "EMAIL", "q_d"),

            # --- API Keys WITH '@' Symbol (Instructor Edge Cases, 18-22) ---
            ("sk-proj-abc@123xyz789def456", True, "API_KEY", "q1"),
            ("sk-live-user@token9988776655", True, "API_KEY", "q1"),
            ("ghp_aB3@dE5fG7hI9jK1lM3nO5pQ7rS9", True, "API_KEY", "q1"),
            ("AIzaSyD@9876543210abcdefGHIJ", True, "API_KEY", "q1"),
            ("x9K2mP@8vLqR4wZ7nB3tY6jH99", True, "API_KEY", "q1"),

            # --- Standard Vendor API Keys (23-26) ---
            ("AKIAIOSFODNN7EXAMPLE1234", True, "API_KEY", "q1"),
            ("pk_live_51H8x9K2mP8vLqR4wZ7n", True, "API_KEY", "q1"),
            ("xoxb-123456789012-1234567890123-abcdef", True, "API_KEY", "q1"),
            ("ya29.a0AfH6SMBx9K2mP8vLqR4wZ7n", True, "API_KEY", "q1"),

            # --- Valid & Invalid Phone Numbers (27-30) ---
            ("09171234567", True, "PHONE", "q1"),
            ("+639987654321", True, "PHONE", "q1"),
            ("09123", False, "NONE", "q_d"),
            ("+63912abc6789", False, "PHONE", "q_d"),

            # --- Normal Text / Non-PII Words (31-32) ---
            ("Automata", False, "NONE", "q_d"),
            ("CompilerDesign2026", False, "NONE", "q_d"),
        ]

        for token, exp_accepted, exp_type, exp_state in test_cases:
            with self.subTest(token=token):
                res = self.engine.inspect_token(token)
                self.assertEqual(res.accepted, exp_accepted, f"Failed acceptance for {token}")
                self.assertEqual(res.pii_type, exp_type, f"Wrong PII type for {token}")
                self.assertEqual(res.final_state, exp_state, f"Wrong final state for {token}")

    def test_in_memory_redaction_tags(self):
        prompt = "Contact john.doe@email.com with key sk-proj-abc123xyz789def456 or +639123456789."
        output = self.engine.process_text(prompt)
        self.assertEqual(output["pii_count"], 3)
        self.assertEqual(
            output["redacted_text"],
            "Contact [EMAIL_01] with key [API_KEY_02] or [PHONE_03]."
        )


class TestFormattingAndAutomata(unittest.TestCase):
    def setUp(self):
        self.engine = PIIAutomatonEngine()

    def test_line_breaks_and_spacing_preserved(self):
        text = "Name:  Ana\r\nEmail: ana@mail.com\n\n\tPhone: +639123456789\n"
        out = self.engine.process_text(text)["redacted_text"]
        self.assertEqual(out, "Name:  Ana\r\nEmail: [EMAIL_01]\n\n\tPhone: [PHONE_02]\n")

    def test_csv_fields_and_brackets(self):
        out = self.engine.process_text('id,email,phone\n1,"ana@mail.com",09171234567\n(bob@mail.org)')
        self.assertEqual(out["pii_count"], 3)
        self.assertIn('1,"[EMAIL_01]",[PHONE_02]', out["redacted_text"])
        self.assertTrue(out["redacted_text"].endswith("([EMAIL_03])"))

    def test_long_plain_word_is_not_an_api_key(self):
        res = self.engine.inspect_token("internationalization-and-localization")
        self.assertFalse(res.accepted)

    def test_generic_key_needs_letter_and_digit(self):
        self.assertFalse(self.engine.inspect_token("12345678901234567890").accepted)
        self.assertTrue(self.engine.inspect_token("abcdefghij1234567890").accepted)

    def test_phone_with_dashes(self):
        self.assertTrue(self.engine.inspect_token("+63-912-345-6789").accepted)
        self.assertFalse(self.engine.inspect_token("+63--912-345-6789").accepted)

    def test_trace_and_path_are_reported(self):
        res = self.engine.process_text("a@b.co")["tokens"][0]
        self.assertEqual(res["dfa_id"], "email")
        self.assertEqual([s["new_state"] for s in res["steps"]][-1], "q_tld2")
        self.assertEqual(res["path"][0], "start")
        self.assertEqual(res["path"][-1], "TLD (2+ letters)")

    def test_diagrams_have_start_and_accepting_nodes(self):
        for dfa in self.engine.describe_automata():
            self.assertEqual(dfa["nodes"][0]["id"], "start")
            self.assertTrue(any(n["accepting"] for n in dfa["nodes"]), dfa["id"])
            self.assertTrue(dfa["edges"])

    def test_same_token_gives_same_answer_twice(self):
        a = self.engine.inspect_token("john.doe@email.com")
        b = self.engine.inspect_token("john.doe@email.com")
        self.assertEqual((a.accepted, a.final_state), (b.accepted, b.final_state))


if __name__ == "__main__":
    unittest.main(verbosity=2)