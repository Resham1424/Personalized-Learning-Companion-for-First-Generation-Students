(function () {
  const chatMessages = document.getElementById('chat-messages');
  const chatInput = document.getElementById('chat-input');
  const chatSendBtn = document.getElementById('chat-send-btn');

  if (!chatMessages || !chatInput || !chatSendBtn) return;

  /* ── Markdown renderer ── */
  const renderMarkdown = (value) => {
    const input = value || '';
    if (window.marked && window.DOMPurify) {
      const html = window.marked.parse(input, { breaks: true });
      return window.DOMPurify.sanitize(html);
    }
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  };

  /* ── Build resume-context string for the AI ── */
  const getResumeContext = () => {
    if (typeof RESUME_ANALYSIS !== 'undefined' && RESUME_ANALYSIS) {
      return JSON.stringify(RESUME_ANALYSIS);
    }
    return '';
  };

  /* ── Add a message bubble ── */
  const addMessage = (text, isUser, audioData, mime) => {
    const messageText = text || '';
    const msg = document.createElement('div');
    msg.className = `chat-message ${isUser ? 'user' : 'bot'}`;

    const sender = document.createElement('div');
    sender.className = 'sender';
    sender.textContent = isUser ? 'You' : 'AI Advisor';

    const body = document.createElement('div');
    body.className = 'text';
    if (isUser) {
      body.textContent = messageText;
    } else {
      body.innerHTML = renderMarkdown(messageText);
    }

    msg.appendChild(sender);
    msg.appendChild(body);

    /* ── Audio player (when TTS is available) ── */
    if (!isUser && audioData) {
      const audioRow = document.createElement('div');
      audioRow.className = 'audio-row';

      const shell = document.createElement('div');
      shell.className = 'audio-shell';

      const label = document.createElement('div');
      label.className = 'audio-label';
      const dot = document.createElement('span');
      dot.className = 'audio-dot';
      const labelText = document.createElement('span');
      labelText.textContent = 'Audio reply';
      label.appendChild(dot);
      label.appendChild(labelText);

      const audioEl = new Audio();
      audioEl.className = 'hidden-audio';
      audioEl.preload = 'metadata';
      const safeMime = mime || 'audio/mpeg';
      audioEl.src = `data:${safeMime};base64,${audioData}`;

      const player = document.createElement('div');
      player.className = 'audio-player';

      const playBtn = document.createElement('button');
      playBtn.className = 'audio-play-btn';
      playBtn.type = 'button';
      playBtn.textContent = '\u25B6';

      const progressOuter = document.createElement('div');
      progressOuter.className = 'audio-progress';
      const progressInner = document.createElement('div');
      progressInner.className = 'audio-progress-inner';
      progressOuter.appendChild(progressInner);

      const timeEl = document.createElement('div');
      timeEl.className = 'audio-time';
      timeEl.textContent = '0:00';

      const fmtTime = (sec) => {
        if (!Number.isFinite(sec)) return '0:00';
        const m = Math.floor(sec / 60);
        const s = Math.floor(sec % 60).toString().padStart(2, '0');
        return `${m}:${s}`;
      };

      const updateProgress = () => {
        const cur = audioEl.currentTime || 0;
        const dur = audioEl.duration || 0;
        const pct = dur ? Math.min(100, (cur / dur) * 100) : 0;
        progressInner.style.width = `${pct}%`;
        timeEl.textContent = `${fmtTime(cur)}${dur ? ` / ${fmtTime(dur)}` : ''}`;
      };

      playBtn.addEventListener('click', () => {
        if (audioEl.paused) audioEl.play().catch(() => {});
        else audioEl.pause();
      });
      audioEl.addEventListener('play', () => { playBtn.textContent = '\u275A\u275A'; });
      audioEl.addEventListener('pause', () => { playBtn.textContent = '\u25B6'; });
      audioEl.addEventListener('ended', () => { playBtn.textContent = '\u25B6'; progressInner.style.width = '0%'; });
      audioEl.addEventListener('timeupdate', updateProgress);
      audioEl.addEventListener('loadedmetadata', updateProgress);
      progressOuter.addEventListener('click', (e) => {
        const rect = progressOuter.getBoundingClientRect();
        const ratio = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
        if (Number.isFinite(audioEl.duration)) audioEl.currentTime = ratio * audioEl.duration;
      });

      player.appendChild(playBtn);
      player.appendChild(progressOuter);
      player.appendChild(timeEl);

      shell.appendChild(label);
      shell.appendChild(player);
      shell.appendChild(audioEl);
      audioRow.appendChild(shell);
      msg.appendChild(audioRow);
    }

    chatMessages.appendChild(msg);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  };

  /* ── Typing indicator ── */
  const showTyping = () => {
    const typing = document.createElement('div');
    typing.className = 'chat-message bot typing-msg';
    const dots = document.createElement('div');
    dots.className = 'typing-indicator';
    for (let i = 0; i < 3; i++) {
      const dot = document.createElement('div');
      dot.className = 'typing-dot';
      dots.appendChild(dot);
    }
    typing.appendChild(dots);
    chatMessages.appendChild(typing);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return typing;
  };

  const removeTyping = () => {
    const typing = chatMessages.querySelector('.typing-msg');
    if (typing) typing.remove();
  };

  /* ── Send handler ── */
  const sendChat = async () => {
    const userMessage = chatInput.value.trim();
    if (!userMessage) return;

    addMessage(userMessage, true);
    chatInput.value = '';
    chatSendBtn.disabled = true;
    showTyping();

    try {
      const res = await fetch('/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMessage,
          context: getResumeContext(),
        }),
      });

      removeTyping();

      if (res.ok) {
        const data = await res.json();
        addMessage(
          data.reply || 'Sorry, I could not process that.',
          false,
          data.audio,
          data.mime
        );
      } else {
        const errData = await res.json().catch(() => ({}));
        addMessage('Error: ' + (errData.error || 'Unknown server error'));
      }
    } catch (err) {
      removeTyping();
      addMessage('Connection error. Please check your network.');
    }

    chatSendBtn.disabled = false;
    chatInput.focus();
  };

  chatSendBtn.addEventListener('click', sendChat);
  chatInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendChat();
  });
})();
