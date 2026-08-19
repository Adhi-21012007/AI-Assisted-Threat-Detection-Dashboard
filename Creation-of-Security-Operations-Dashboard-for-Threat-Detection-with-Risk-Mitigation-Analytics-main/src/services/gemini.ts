const API_KEY = import.meta.env.VITE_GROQ_API_KEY;

export async function askGemini(prompt: string) {
  try {
    const response = await fetch(
      "https://api.groq.com/openai/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${API_KEY}`,
        },
        body: JSON.stringify({
          model: "openai/gpt-oss-120b",
          messages: [
            {
              role: "user",
              content: prompt,
            },
          ],
          temperature: 0.5,
        }),
      }
    );

    const data = await response.json();

    console.log(data);

    return data.choices[0].message.content;
  } catch (err) {
    console.error(err);
    return "AI Service Error";
  }
}