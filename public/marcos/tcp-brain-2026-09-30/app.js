(() => {
  const player = document.querySelector("#player");
  const status = document.querySelector("#status");
  const progressBar = document.querySelector("#progressBar");
  const rate = document.querySelector("#rate");
  const rateLabel = document.querySelector("#rateLabel");
  const copyLink = document.querySelector("#copyLink");
  const durations = [
    28.704, 30.36, 29.184, 30.36, 33.96,
    31.896, 22.296, 22.944, 30.36
  ];
  const starts = [];
  let acc = 0;
  durations.forEach((d) => { starts.push(acc); acc += d; });

  let blocks = [];
  let activeBlock = -1;
  let raf = 0;

  function clearHighlight() {
    document.querySelectorAll("#narration .active")
      .forEach((el) => el.classList.remove("active"));
  }
  function prepareKaraoke() {
    blocks = [];
    document.querySelectorAll("#narration [data-segment]").forEach((p) => {
      const raw = p.textContent.trim();
      p.innerHTML = "";
      const segment = document.createElement("span");
      segment.className = "segment";
      const words = [];
      const weights = [];

      raw.split(/(\s+)/).forEach((piece) => {
        if (!piece) return;
        if (/^\s+$/.test(piece)) {
          segment.appendChild(document.createTextNode(piece));
          return;
        }
        const word = document.createElement("span");
        word.className = "word";
        word.textContent = piece;
        segment.appendChild(word);
        words.push(word);
        const clean = piece.replace(/[^A-Za-zÀ-ÿ0-9]/g, "");
        weights.push(Math.max(1, clean.length));
      });

      p.appendChild(segment);
      blocks.push({
        container: p,
        segment,
        words,
        weights,
        total: weights.reduce((a, b) => a + b, 0),
      });
    });
  }
  function segmentForTime(t) {
    for (let i = 0; i < durations.length; i += 1) {
      if (t < starts[i] + durations[i]) return i;
    }
    return durations.length - 1;
  }

  function syncKaraoke() {
    if (!blocks.length) return;
    const t = player.currentTime || 0;
    const idx = segmentForTime(t);

    if (idx !== activeBlock) {
      clearHighlight();
      activeBlock = idx;
      const block = blocks[idx];
      block.container.classList.add("active");
      block.segment.classList.add("active");
      if (window.innerWidth < 900) {
        block.container.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }

    const block = blocks[idx];
    block.words.forEach((w) => w.classList.remove("active"));
    const local = Math.max(0, Math.min(durations[idx], t - starts[idx]));
    const target = (local / durations[idx]) * block.total;
    let sum = 0;
    let wordIndex = Math.max(0, block.words.length - 1);
    for (let i = 0; i < block.weights.length; i += 1) {
      sum += block.weights[i];
      if (target <= sum) {
        wordIndex = i;
        break;
      }
    }
    if (block.words[wordIndex]) block.words[wordIndex].classList.add("active");

    if (Number.isFinite(player.duration) && player.duration > 0) {
      progressBar.style.width = ((t / player.duration) * 100) + "%";
    }
  }

  function animate() {
    syncKaraoke();
    if (!player.paused && !player.ended) {
      raf = requestAnimationFrame(animate);
    }
  }

  document.querySelector("#play").addEventListener("click", async () => {
    if (player.ended || (player.duration && player.currentTime >= player.duration - 0.1)) {
      player.currentTime = 0;
    }
    player.playbackRate = Number(rate.value);
    try {
      await player.play();
      status.textContent = "Zagan · reproduzindo…";
      cancelAnimationFrame(raf);
      animate();
    } catch {
      status.textContent = "O navegador bloqueou o áudio. Toque em Reproduzir novamente.";
    }
  });
  document.querySelector("#pause").addEventListener("click", () => {
    player.pause();
    status.textContent = "Pausado.";
  });

  document.querySelector("#stop").addEventListener("click", () => {
    player.pause();
    player.currentTime = 0;
    activeBlock = -1;
    clearHighlight();
    progressBar.style.width = "0%";
    status.textContent = "Interrompido.";
  });

  rate.addEventListener("input", () => {
    const value = Number(rate.value);
    player.playbackRate = value;
    rateLabel.textContent = value.toFixed(2).replace(/0+$/, "").replace(/\.$/, "") + "×";
  });

  player.addEventListener("loadedmetadata", () => {
    status.textContent = "Zagan pronta · " + Math.round(player.duration / 60) + " min de narração.";
  });

  player.addEventListener("timeupdate", syncKaraoke);
  player.addEventListener("ended", () => {
    cancelAnimationFrame(raf);
    clearHighlight();
    activeBlock = -1;
    progressBar.style.width = "100%";
    status.textContent = "Leitura concluída.";
  });
  player.addEventListener("error", () => {
    status.textContent = "Não foi possível carregar o áudio Zagan.";
  });

  if (copyLink) {
    copyLink.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(location.href.split("#")[0]);
        copyLink.textContent = "Link copiado";
        setTimeout(() => { copyLink.textContent = "Copiar link"; }, 1800);
      } catch {
        copyLink.textContent = "Copie pela barra do navegador";
      }
    });
  }

  prepareKaraoke();
})();
