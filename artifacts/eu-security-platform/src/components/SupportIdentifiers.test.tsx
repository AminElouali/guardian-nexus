import assert from "node:assert/strict";
import { test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { SupportIdentifiers } from "./SupportIdentifiers";

test("signed-in user can copy their ID before joining a workspace", () => {
  const markup = renderToStaticMarkup(
    createElement(SupportIdentifiers, { userId: "user_demo_person_b" }),
  );

  assert.match(markup, /identificadores técnicos para soporte y demostraciones/);
  assert.match(markup, /user_demo_person_b/);
  assert.match(markup, /data-testid="button-copy-support-id-user"/);
  assert.match(markup, /Copiar identificador de usuario/);
  assert.doesNotMatch(markup, /Identificador del espacio/);
  assert.match(markup, /ni añaden personas al espacio/);
});

test("team view shows and offers copy actions for both identifiers", () => {
  const markup = renderToStaticMarkup(
    createElement(SupportIdentifiers, {
      userId: "user_demo_owner",
      workspaceId: "33333333-3333-4333-8333-333333333333",
    }),
  );

  assert.match(markup, /user_demo_owner/);
  assert.match(markup, /33333333-3333-4333-8333-333333333333/);
  assert.match(markup, /data-testid="button-copy-support-id-user"/);
  assert.match(markup, /data-testid="button-copy-support-id-workspace"/);
  assert.match(markup, /Copiar identificador del espacio/);
});
