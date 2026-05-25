import json
import unittest
from unittest.mock import patch

import openai_sip_webhook as webhook


class CallLifecycleTests(unittest.TestCase):
    def test_default_max_call_seconds_is_ten_minutes(self):
        self.assertEqual(webhook.OPENAI_MAX_CALL_SECONDS, 600.0)

    def test_end_call_session_update_registers_tool(self):
        event = webhook.build_end_call_session_update()

        self.assertEqual(event["type"], "session.update")
        self.assertEqual(event["session"]["tool_choice"], "auto")
        tools = event["session"]["tools"]
        self.assertEqual(tools[0]["type"], "function")
        self.assertEqual(tools[0]["name"], "end_call")
        self.assertEqual(tools[0]["parameters"]["type"], "object")

    @patch("openai_sip_webhook.requests.post")
    def test_accept_call_instructions_tell_model_when_to_end_call(self, post):
        post.return_value.ok = True
        post.return_value.status_code = 200

        webhook.accept_call("rtc_test")

        body = json.loads(post.call_args.kwargs["data"])
        self.assertIn("end_call", body["instructions"])
        self.assertIn("desped", body["instructions"].lower())

    def test_detects_end_call_from_function_arguments_done_event(self):
        event = {
            "type": "response.function_call_arguments.done",
            "name": "end_call",
            "arguments": "{}",
        }

        self.assertTrue(webhook.is_end_call_tool_event(event))

    def test_detects_end_call_from_response_done_output(self):
        event = {
            "type": "response.done",
            "response": {
                "output": [
                    {"type": "function_call", "name": "end_call", "arguments": "{}"},
                ]
            },
        }

        self.assertTrue(webhook.is_end_call_tool_event(event))

    @patch("openai_sip_webhook.requests.post")
    def test_hangup_call_posts_to_realtime_hangup_endpoint(self, post):
        post.return_value.ok = True
        post.return_value.status_code = 200

        resp = webhook.hangup_call("rtc_test")

        self.assertIs(resp, post.return_value)
        url = post.call_args.args[0]
        self.assertEqual(url, "https://api.openai.com/v1/realtime/calls/rtc_test/hangup")
        self.assertEqual(post.call_args.kwargs["headers"], webhook.AUTH_HEADER)

    def test_farewell_response_is_audio_response(self):
        event = webhook.build_farewell_response_create("agent_end_call")

        self.assertEqual(event["type"], "response.create")
        self.assertIn("response", event)
        self.assertIn("despedida", event["response"]["instructions"].lower())
        json.dumps(event)


if __name__ == "__main__":
    unittest.main()
