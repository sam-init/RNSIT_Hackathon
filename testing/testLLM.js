// nvidiaTest.js
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: "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",
  baseURL: "https://integrate.api.nvidia.com/v1"
});

async function testNvidia() {
  try {
    const res = await client.chat.completions.create({
      model: "meta/llama3-70b-instruct", // ✅ most stable
      messages: [
        {
          role: "user",
          content: "what is 2 + 10"
        }
      ],
      temperature: 0.2
    });

    console.log("✅ SUCCESS:");
    console.log(res.choices[0].message.content);

  } catch (err) {
    console.error("❌ ERROR:");
    console.error(err.message);
  }
}

testNvidia();