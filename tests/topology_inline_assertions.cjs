"use strict";

const assert = require("node:assert/strict");
const compactScope = scope => scope === "全部协议 · 全部端口" ? "全协议 · 全端口" : scope.replaceAll(" · ", " ").replaceAll(", ", ",");

async function inlineSnapshot(page) {
  return page.locator("[data-topology-graph]").evaluate(graph => {
    const rect = node => { const box = node.getBoundingClientRect(); return {left: box.left, top: box.top, right: box.right, bottom: box.bottom, width: box.width, height: box.height}; };
    const visible = node => Boolean(node && node.getClientRects().length && getComputedStyle(node).display !== "none" && getComputedStyle(node).visibility !== "hidden" && !node.closest("[hidden]"));
    return {box: rect(graph), floating: graph.querySelectorAll("[data-topology-edge-label], .topology-edge-label").length,
      nodes: [...graph.querySelectorAll("[data-topology-node]")].map(node => {
        const ports = node.querySelector("[data-topology-node-ports]"), marker = node.querySelector(".topology-node-selected"), more = node.querySelector(".topology-node-ports-more");
        return {id: node.dataset.topologyNode, selected: node.getAttribute("aria-pressed") === "true", box: rect(node), aria: node.getAttribute("aria-label") || "",
          name: rect(node.querySelector("strong")), state: rect(node.querySelector(".topology-node-state")),
          marker: {visible: visible(marker), text: marker?.textContent, box: marker ? rect(marker) : null},
          ports: {exists: Boolean(ports), visible: visible(ports), title: ports?.getAttribute("title") || "", box: ports ? rect(ports) : null,
            lines: [...node.querySelectorAll(".topology-node-port")].map(line => ({text: line.textContent, scope: line.dataset.topologyScope,
              title: line.getAttribute("title"), visible: visible(line), box: rect(line), font: parseFloat(getComputedStyle(line).fontSize),
              clipped: line.scrollWidth > line.clientWidth + 1, ellipsis: getComputedStyle(line).textOverflow})),
            more: {visible: visible(more), text: more?.textContent || "", box: more ? rect(more) : null}}};
      })};
  });
}

function geometryFindings(snapshot, fit = true) {
  const outside = (one, two) => one.left < two.left - 1 || one.right > two.right + 1 || one.top < two.top - 1 || one.bottom > two.bottom + 1;
  const overlaps = (one, two) => Math.min(one.right, two.right) - Math.max(one.left, two.left) > 1 && Math.min(one.bottom, two.bottom) - Math.max(one.top, two.top) > 1;
  const findings = [];
  for (const [index, node] of snapshot.nodes.entries()) {
    if (fit && outside(node.box, snapshot.box)) findings.push({kind: "card-outside-canvas", node: node.id});
    for (const [kind, box] of [["name", node.name], ["state", node.state]]) if (outside(box, node.box)) findings.push({kind: kind + "-outside-own-card", node: node.id});
    for (const other of snapshot.nodes.slice(index + 1)) if (overlaps(node.box, other.box)) findings.push({kind: "cards-overlap", nodes: [node.id, other.id]});
    if (node.marker.visible) {
      if (outside(node.marker.box, node.box)) findings.push({kind: "current-outside-own-card", node: node.id});
      for (const [kind, box] of [["name", node.name], ["state", node.state]]) if (overlaps(node.marker.box, box)) findings.push({kind: "current-covers-" + kind, node: node.id});
    }
    const items = node.ports.lines.filter(line => line.visible).map(line => ({kind: "scope", ...line}));
    if (node.ports.more.visible) items.push({kind: "more", ...node.ports.more});
    for (const [lineIndex, line] of items.entries()) {
      if (outside(line.box, node.box)) findings.push({kind: "port-outside-own-card", node: node.id, text: line.text});
      for (const [kind, box] of [["name", node.name], ["state", node.state], ...(node.marker.visible ? [["current", node.marker.box]] : [])]) {
        if (overlaps(line.box, box)) findings.push({kind: "port-covers-" + kind, node: node.id, text: line.text});
      }
      for (const other of items.slice(lineIndex + 1)) if (overlaps(line.box, other.box)) findings.push({kind: "port-rows-overlap", node: node.id});
    }
  }
  return findings;
}

function assertCompactCards(snapshot) {
  for (const node of snapshot.nodes) {
    const count = node.ports.lines.length, more = node.ports.more.visible;
    const [minimum, maximum] = more ? [92, 102] : count === 2 ? [78, 92] : count === 1 ? [64, 78] : [48, 60];
    assert.ok(node.box.height >= minimum && node.box.height <= maximum,
      `${node.id}: ${count} inline rows${more ? " plus extra count" : ""} use compact content height (${node.box.height}px, expected ${minimum}–${maximum})`);
  }
}

async function assertCardEdges(page) {
  const endpoints = await page.locator("[data-topology-graph]").evaluate(graph => {
    const cards = new Map([...graph.querySelectorAll("[data-topology-node]")].map(node => [node.dataset.topologyNode, node.getBoundingClientRect()]));
    const edges = [...graph.querySelectorAll("[data-topology-edge], [data-topology-spoke]")];
    return edges.flatMap(edge => {
      const source = cards.get(edge.dataset.source), target = cards.get(edge.dataset.target);
      // User-created overlaps and the intentionally compressed 40-node stress
      // fixture cannot offer a visible endpoint between two intersecting cards.
      if (source.left < target.right + 20 && source.right > target.left - 20 && source.top < target.bottom + 20 && source.bottom > target.top - 20) return [];
      const matrix = edge.getScreenCTM();
      return [["source", source, 0], ["target", target, edge.getTotalLength()]].map(([kind, box, length]) => {
        const point = edge.getPointAtLength(length).matrixTransform(matrix);
        return {source: edge.dataset.source, target: edge.dataset.target, kind,
          distance: Math.max(box.left - point.x, point.x - box.right, box.top - point.y, point.y - box.bottom)};
      });
    });
  });
  for (const endpoint of endpoints) assert.ok(endpoint.distance >= 5 && endpoint.distance <= 9,
    `${endpoint.source}→${endpoint.target} ${endpoint.kind}: endpoint stays 7px outside the actual content-sized card (${endpoint.distance}px)`);
}

async function assertInlinePorts(page, links, selectedId, direction, overview = false) {
  const snapshot = await inlineSnapshot(page);
  assertCompactCards(snapshot);
  assert.equal(snapshot.floating, 0, "SVG floating port labels are completely removed");
  const selectedMarkers = snapshot.nodes.filter(node => node.marker.visible);
  assert.deepEqual(selectedMarkers.map(node => node.id), overview ? [] : [selectedId], "only the selected relation node displays the current marker");
  if (!overview) assert.equal(selectedMarkers[0].marker.text, "当前");
  const expected = overview ? [] : links.filter(link => direction === "forward" ? link.source === selectedId : link.target === selectedId);
  for (const node of snapshot.nodes) {
    const link = expected.find(link => (direction === "forward" ? link.target : link.source) === node.id);
    const scopes = link?.scopes || [];
    assert.ok(node.ports.exists, "each card has its inline port container");
    assert.deepEqual(node.ports.lines.map(line => line.scope), scopes.slice(0, 2), "card scopes correspond exactly to this directed edge, with no stale ports");
    assert.deepEqual(node.ports.lines.map(line => line.text), scopes.slice(0, 2).map(compactScope), "the visible compact scope never changes its protocol or port values");
    assert.equal(node.ports.lines.every(line => line.visible), true);
    assert.equal(node.ports.visible, scopes.length > 0, "overview, selected, unknown, and unrelated cards have no visible port block");
    if (!scopes.length) assert.equal(node.ports.title, "", "unrelated cards retain no stale permission tooltip");
    for (const line of node.ports.lines) {
      assert.equal(line.title, line.scope, "each displayed scope keeps its full text in the title");
      if (line.clipped) assert.equal(line.ellipsis, "ellipsis", "long scope overflow uses visual ellipsis, not lost DOM text");
      if (line.text.length <= 14) assert.equal(line.clipped, false, "common short protocol/port scopes are completely visible");
    }
    for (const scope of scopes) {
      assert.ok(node.aria.includes(scope), "button accessibility text includes every full scope, including extra rows");
      assert.ok(node.ports.title.includes(scope), "port block tooltip includes every full scope");
    }
    if (scopes.length) assert.ok(node.ports.title.includes(direction === "forward" ? "当前节点可访问此节点" : "此节点可访问当前节点"), "port tooltip identifies the correct access direction");
    assert.equal(node.ports.more.visible, scopes.length > 2, "an overflow count appears only when more than two scopes exist");
    if (scopes.length > 2) assert.match(node.ports.more.text, new RegExp(`另\\s*${scopes.length - 2}\\s*项.*见详情`));
  }
  return snapshot;
}

module.exports = {assertCardEdges, assertCompactCards, assertInlinePorts, compactScope, geometryFindings, inlineSnapshot};
