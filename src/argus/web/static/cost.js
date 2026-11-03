// The cost bar (D-094): the AI spend this month against the cap, refreshed every 30 s. Its
// requests are background ones: they never keep a session alive (Q-A1).
(function () {
  "use strict";
  var bar = document.getElementById("costbar");
  if (!bar) { return; }
  var meter = document.getElementById("cost-meter");
  var label = document.getElementById("cost-text");
  function money(v) { return "$" + v.toFixed(2); }
  function show(c) {
    meter.max = c.cap_usd;
    meter.low = c.cap_usd * 0.5;
    meter.high = c.paid_until_usd;
    meter.value = Math.min(c.month_usd, c.cap_usd);
    var text = money(c.month_usd) + " of " + money(c.cap_usd) + " this month · today " +
      money(c.today_usd) + (c.daily_cap_usd !== null ? " of " + money(c.daily_cap_usd) : "") +
      " (" + c.calls_today + " calls)";
    if (c.stopped) { text += " · AI STOPPED"; }
    label.textContent = text;
    var near = c.month_usd >= c.paid_until_usd;
    bar.classList.toggle("cost-near", near);
    bar.title = "Paid AI until " + money(c.paid_until_usd) + " this month, then the free" +
      " providers; updated " + new Date(c.at).toLocaleTimeString();
  }
  function tick() {
    fetch("/api/cost", {
      credentials: "same-origin",
      headers: { "Accept": "application/json", "X-Argus-Background": "1" }
    })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (c) { if (c) { show(c); } })
      .catch(function () { /* the next tick tries again */ });
  }
  tick();
  setInterval(tick, 30000);
}());
