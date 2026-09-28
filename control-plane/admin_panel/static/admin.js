/* Verdent Platform — admin panel progressive enhancement.
 *
 * **Everything here is additive.** Every form, every link and every filter in
 * the panel works with this file absent and JavaScript disabled: search is a
 * real GET form, sorting and paging are real links, destructive actions are
 * real POSTs. This file only makes those things nicer. Nothing may be moved
 * out of the HTML and into here — a panel that needs JavaScript to ban a
 * customer is a panel that cannot be used from a locked-down browser, and the
 * live-search path is exactly the one an operator reaches for during an
 * incident.
 *
 * Loaded with `defer`, after htmx.min.js, so the DOM is parsed by the time it
 * runs and `htmx` is defined.
 */

(function () {
  "use strict";

  /* -------------------------------------------------------------------------
   * 1. Confirmation on destructive actions
   *
   * `data-confirm="..."` on a <form> asks before submitting. Captured at the
   * document level so it also applies to markup swapped in by HTMX — a
   * per-element listener would silently stop working for any row that arrived
   * after page load, which is precisely the rows an operator acts on.
   *
   * Cancelling calls preventDefault, which for a plain form stops the submit.
   * ---------------------------------------------------------------------- */
  document.addEventListener(
    "submit",
    function (event) {
      var form = event.target;
      if (!form || form.nodeName !== "FORM") return;

      var message = form.getAttribute("data-confirm");
      if (!message) return;
      if (!window.confirm(message)) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    },
    true // capture: run before any other submit handler
  );

  /* -------------------------------------------------------------------------
   * 2. Disclosure — `data-toggle="#selector"`
   *
   * Shows/hides the element the selector names. Used for the ban form on the
   * customer page, which is a large, destructive panel that should not be
   * open by default. The element carries `hidden` in the markup, so with JS
   * off it is simply never shown — the safe default for a destructive form.
   * ---------------------------------------------------------------------- */
  function toggleTarget(button) {
    var selector = button.getAttribute("data-toggle");
    if (!selector) return null;
    try {
      return document.querySelector(selector);
    } catch (err) {
      return null; // a malformed selector must not break the rest of the page
    }
  }

  function setExpanded(button, expanded) {
    var target = toggleTarget(button);
    if (!target) return;
    target.hidden = !expanded;
    button.setAttribute("aria-expanded", expanded ? "true" : "false");
    button.setAttribute("aria-controls", target.id || "");

    if (expanded) {
      // Put the caret where the operator has to type. Without this, opening a
      // form leaves focus on the button and the first keystroke does nothing.
      var field = target.querySelector("textarea, input:not([type=hidden]):not([type=button]):not([type=submit]), select");
      if (field) field.focus();
      target.scrollIntoView({ block: "nearest" });
    }
  }

  // Delegated, for the same reason as the submit handler: rows and forms
  // arrive from HTMX after load.
  document.addEventListener("click", function (event) {
    var button = event.target.closest ? event.target.closest("[data-toggle]") : null;
    if (!button) return;
    event.preventDefault();

    var target = toggleTarget(button);
    if (!target) return;
    // Toggling is driven by the target's current state, not the button's, so
    // the button label stays honest whichever control opened the panel.
    setExpanded(button, target.hidden);
  });

  /* -------------------------------------------------------------------------
   * 3. Surface HTMX failures
   *
   * HTMX's default behaviour on a failed request is to swap nothing and say
   * nothing. For a live search that reads as "no results" when the truth is
   * "the request failed" — an operator then concludes a customer has no
   * configs when the server just 500'd. A 403 has the same problem from the
   * other side: the operator's role cannot see this table, and silence looks
   * like an empty table.
   *
   * The message is inserted above the swap target so it does not get replaced
   * by the next successful request.
   * ---------------------------------------------------------------------- */
  function reportFailure(target, text) {
    if (!target) return;
    var existing = document.getElementById("htmx-error");
    if (existing) existing.remove();

    var box = document.createElement("div");
    box.id = "htmx-error";
    box.className = "alert alert-bad";
    box.setAttribute("role", "alert");
    box.textContent = text;
    target.parentNode.insertBefore(box, target);
  }

  document.addEventListener("htmx:responseError", function (event) {
    var status = event.detail.xhr ? event.detail.xhr.status : 0;
    var target = event.detail.target;
    if (status === 403) {
      reportFailure(target, "دسترسی شما به این بخش مجاز نیست. با یک مدیر ارشد تماس بگیرید.");
    } else if (status === 404) {
      reportFailure(target, "این مورد پیدا نشد — ممکن است هم‌زمان توسط ادمین دیگری تغییر کرده باشد.");
    } else {
      reportFailure(target, "بارگذاری نتیجه ناموفق بود (کد " + status + "). دوباره تلاش کنید.");
    }
  });

  document.addEventListener("htmx:sendError", function (event) {
    reportFailure(
      event.detail.target,
      "ارتباط با سرور برقرار نشد. اتصال شبکه را بررسی کنید و دوباره تلاش کنید."
    );
  });

  // A successful swap clears the previous failure, so a stale error does not
  // sit above a table that has since loaded correctly.
  document.addEventListener("htmx:afterSwap", function () {
    var existing = document.getElementById("htmx-error");
    if (existing) existing.remove();
  });

  /* -------------------------------------------------------------------------
   * 4. Keep the browser's own navigation usable
   *
   * The pager and the sort headers swap the table in place. When the operator
   * then presses back, the browser restores the previous URL but not the rows
   * HTMX swapped, so the address bar and the table disagree. Reloading on
   * popstate is the cheap, honest fix: the server renders the page the URL
   * names.
   * ---------------------------------------------------------------------- */
  window.addEventListener("popstate", function (event) {
    if (event.state && event.state.htmx) return; // HTMX handles its own history
    if (document.querySelector("[data-list-form]")) {
      window.location.reload();
    }
  });
})();
