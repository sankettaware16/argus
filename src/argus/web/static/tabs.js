// The investigation page's tabs (D-102). Without this script every section shows, one after
// another, and the tabs are plain in-page links.
(function () {
  "use strict";
  var article = document.getElementById("inv");
  if (!article) { return; }
  var panels = Array.prototype.slice.call(article.querySelectorAll(".tab-panel"));
  var links = Array.prototype.slice.call(article.querySelectorAll(".tabs a"));
  if (!panels.length || !links.length) { return; }
  function show(id) {
    var found = panels.some(function (p) { return p.id === id; });
    if (!found) { id = panels[0].id; }
    panels.forEach(function (p) { p.hidden = p.id !== id; });
    links.forEach(function (a) {
      if (a.getAttribute("href") === "#" + id) { a.setAttribute("aria-current", "true"); }
      else { a.removeAttribute("aria-current"); }
    });
  }
  links.forEach(function (a) {
    a.addEventListener("click", function (event) {
      event.preventDefault();
      var id = a.getAttribute("href").slice(1);
      show(id);
      history.replaceState(null, "", "#" + id);
    });
  });
  window.addEventListener("hashchange", function () { show(location.hash.slice(1)); });
  article.classList.add("tabbed");
  var wanted = location.hash.slice(1);
  if (!wanted && new URLSearchParams(location.search).get("columns")) { wanted = "alerts"; }
  show(wanted);
})();
