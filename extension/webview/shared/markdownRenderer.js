// SPDX-License-Identifier: AGPL-3.0-only
(function initMarkdownRenderer(global) {
  const SAFE_LINK_PROTOCOLS = new Set(['http:', 'https:', 'mailto:']);

  function normalizeSafeLink(rawUrl) {
    const value = String(rawUrl || '').trim();
    if (!value) return '';
    try {
      const url = new URL(value);
      return SAFE_LINK_PROTOCOLS.has(url.protocol) ? url.href : '';
    } catch (_) {
      return '';
    }
  }

  function parseInline(text) {
    const source = String(text || '');
    const nodes = [];
    const pattern = /(`[^`\n]+`|\*\*[^*\n]+\*\*|__[^_\n]+__|\*[^*\n]+\*|_[^_\n]+_|\[[^\]\n]+\]\([^) \n]+\))/g;
    let cursor = 0;
    let match;
    while ((match = pattern.exec(source)) !== null) {
      if (match.index > cursor) {
        nodes.push({ type: 'text', text: source.slice(cursor, match.index) });
      }
      const token = match[0];
      if (token.startsWith('`')) {
        nodes.push({ type: 'code', text: token.slice(1, -1) });
      } else if (token.startsWith('**') || token.startsWith('__')) {
        nodes.push({ type: 'strong', children: parseInline(token.slice(2, -2)) });
      } else if (token.startsWith('*') || token.startsWith('_')) {
        nodes.push({ type: 'em', children: parseInline(token.slice(1, -1)) });
      } else {
        const linkMatch = token.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
        const href = normalizeSafeLink(linkMatch?.[2]);
        if (href) {
          nodes.push({
            type: 'link',
            href,
            children: parseInline(linkMatch[1]),
          });
        } else {
          nodes.push({ type: 'text', text: linkMatch?.[1] || token });
        }
      }
      cursor = pattern.lastIndex;
    }
    if (cursor < source.length) {
      nodes.push({ type: 'text', text: source.slice(cursor) });
    }
    return nodes;
  }

  function isTableSeparator(line) {
    return /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(line);
  }

  function splitTableRow(line) {
    return String(line || '')
      .trim()
      .replace(/^\|/, '')
      .replace(/\|$/, '')
      .split('|')
      .map((cell) => cell.trim());
  }

  function parseMarkdown(markdown) {
    const lines = String(markdown || '').replace(/\r\n?/g, '\n').split('\n');
    const blocks = [];
    let index = 0;

    while (index < lines.length) {
      const line = lines[index];
      if (!line.trim()) {
        index += 1;
        continue;
      }

      const fence = line.match(/^\s*```([A-Za-z0-9_+-]*)\s*$/);
      if (fence) {
        const codeLines = [];
        index += 1;
        while (index < lines.length && !/^\s*```\s*$/.test(lines[index])) {
          codeLines.push(lines[index]);
          index += 1;
        }
        if (index < lines.length) index += 1;
        blocks.push({
          type: 'codeBlock',
          language: fence[1] || '',
          text: codeLines.join('\n'),
        });
        continue;
      }

      const heading = line.match(/^\s*(#{1,4})\s+(.+)$/);
      if (heading) {
        blocks.push({
          type: 'heading',
          level: heading[1].length,
          children: parseInline(heading[2]),
        });
        index += 1;
        continue;
      }

      if (index + 1 < lines.length && line.includes('|') && isTableSeparator(lines[index + 1])) {
        const headers = splitTableRow(line).map(parseInline);
        const rows = [];
        index += 2;
        while (index < lines.length && lines[index].includes('|') && lines[index].trim()) {
          rows.push(splitTableRow(lines[index]).map(parseInline));
          index += 1;
        }
        blocks.push({ type: 'table', headers, rows });
        continue;
      }

      const listMatch = line.match(/^\s*([-*+]|\d+\.)\s+(.+)$/);
      if (listMatch) {
        const ordered = /\d+\./.test(listMatch[1]);
        const items = [];
        while (index < lines.length) {
          const item = lines[index].match(/^\s*([-*+]|\d+\.)\s+(.+)$/);
          if (!item || /\d+\./.test(item[1]) !== ordered) break;
          items.push(parseInline(item[2]));
          index += 1;
        }
        blocks.push({ type: 'list', ordered, items });
        continue;
      }

      if (/^\s*>\s?/.test(line)) {
        const quoteLines = [];
        while (index < lines.length && /^\s*>\s?/.test(lines[index])) {
          quoteLines.push(lines[index].replace(/^\s*>\s?/, ''));
          index += 1;
        }
        blocks.push({ type: 'blockquote', children: parseInline(quoteLines.join('\n')) });
        continue;
      }

      const paragraphLines = [line.trim()];
      index += 1;
      while (
        index < lines.length
        && lines[index].trim()
        && !/^\s*(```|#{1,4}\s|[-*+]\s|\d+\.\s|>\s?)/.test(lines[index])
        && !(index + 1 < lines.length && lines[index].includes('|') && isTableSeparator(lines[index + 1]))
      ) {
        paragraphLines.push(lines[index].trim());
        index += 1;
      }
      blocks.push({
        type: 'paragraph',
        children: parseInline(paragraphLines.join('\n')),
      });
    }
    return blocks;
  }

  function appendInlineNodes(parent, nodes, doc) {
    nodes.forEach((node) => {
      if (node.type === 'text') {
        parent.appendChild(doc.createTextNode(node.text));
        return;
      }
      const elementName = {
        code: 'code',
        strong: 'strong',
        em: 'em',
        link: 'a',
      }[node.type];
      if (!elementName) return;
      const element = doc.createElement(elementName);
      if (node.type === 'code') {
        element.textContent = node.text;
      } else {
        appendInlineNodes(element, node.children || [], doc);
      }
      if (node.type === 'link') {
        element.href = node.href;
        element.target = '_blank';
        element.rel = 'noopener noreferrer';
      }
      parent.appendChild(element);
    });
  }

  function renderMarkdown(container, markdown, doc = document) {
    container.replaceChildren();
    const fragment = doc.createDocumentFragment();
    parseMarkdown(markdown).forEach((block) => {
      let element;
      if (block.type === 'heading') {
        element = doc.createElement(`h${block.level}`);
        appendInlineNodes(element, block.children, doc);
      } else if (block.type === 'paragraph') {
        element = doc.createElement('p');
        appendInlineNodes(element, block.children, doc);
      } else if (block.type === 'blockquote') {
        element = doc.createElement('blockquote');
        appendInlineNodes(element, block.children, doc);
      } else if (block.type === 'codeBlock') {
        element = doc.createElement('pre');
        const code = doc.createElement('code');
        code.textContent = block.text;
        if (block.language) code.dataset.language = block.language;
        element.appendChild(code);
      } else if (block.type === 'list') {
        element = doc.createElement(block.ordered ? 'ol' : 'ul');
        block.items.forEach((item) => {
          const li = doc.createElement('li');
          appendInlineNodes(li, item, doc);
          element.appendChild(li);
        });
      } else if (block.type === 'table') {
        element = doc.createElement('div');
        element.className = 'ollama-markdown-table-wrap';
        const table = doc.createElement('table');
        const thead = doc.createElement('thead');
        const headRow = doc.createElement('tr');
        block.headers.forEach((header) => {
          const th = doc.createElement('th');
          appendInlineNodes(th, header, doc);
          headRow.appendChild(th);
        });
        thead.appendChild(headRow);
        const tbody = doc.createElement('tbody');
        block.rows.forEach((row) => {
          const tr = doc.createElement('tr');
          row.forEach((cell) => {
            const td = doc.createElement('td');
            appendInlineNodes(td, cell, doc);
            tr.appendChild(td);
          });
          tbody.appendChild(tr);
        });
        table.append(thead, tbody);
        element.appendChild(table);
      }
      if (element) fragment.appendChild(element);
    });
    container.appendChild(fragment);
  }

  const api = { normalizeSafeLink, parseInline, parseMarkdown, renderMarkdown };
  global.POFMarkdownRenderer = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
