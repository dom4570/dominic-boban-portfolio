import {
  ArrowLeft,
  CalendarDays,
  Eye,
  FileText,
  ImagePlus,
  Loader2,
  Lock,
  Plus,
  Save,
  Search,
  Send,
  Tags,
  Trash2,
  UploadCloud,
} from "lucide-react";
import { motion } from "framer-motion";
import { ChangeEvent, FormEvent, useEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import rehypeSanitize from "rehype-sanitize";
import remarkGfm from "remark-gfm";

type PostStatus = "draft" | "published";

type BlogPost = {
  id: string;
  slug: string;
  title: string;
  summary: string;
  content_md: string;
  cover_image_key: string | null;
  cover_image_url: string | null;
  tags: string[];
  status: PostStatus;
  created_at: string;
  updated_at: string;
  published_at: string | null;
};

type EditorForm = {
  id?: string;
  slug: string;
  title: string;
  summary: string;
  content_md: string;
  cover_image_key: string | null;
  tags: string;
  status: PostStatus;
};

const blankPost: EditorForm = {
  slug: "",
  title: "",
  summary: "",
  content_md: "# New security note\n\nWrite the opening context here.\n\n## Key takeaways\n\n- Finding one\n- Finding two\n",
  cover_image_key: null,
  tags: "Penetration Testing, Security Engineering",
  status: "draft",
};

const fadeUp = {
  hidden: { opacity: 0, y: 24 },
  visible: { opacity: 1, y: 0 },
};

function mediaUrl(key: string | null) {
  return key ? `/media/${key}` : null;
}

function formatDate(value: string | null) {
  if (!value) return "Draft";

  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  }).format(new Date(value));
}

function slugify(value: string) {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 96);
}

async function readJson<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => null);

  if (!response.ok) {
    throw new Error(body?.message || "Request failed");
  }

  return body as T;
}

function BlogChrome({ children, eyebrow = "Dominic Boban / Field Notes" }: { children: React.ReactNode; eyebrow?: string }) {
  return (
    <div className="relative min-h-screen px-5 py-6">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_12%,rgba(252,238,10,0.12),transparent_28%),radial-gradient(circle_at_82%_8%,rgba(255,42,61,0.1),transparent_22%)]" aria-hidden="true" />
      <nav className="relative z-10 mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 rounded-lg border border-white/10 bg-obsidian/70 px-4 py-3 backdrop-blur-xl">
        <a href="/" className="glitch-control inline-flex items-center gap-2 text-sm font-semibold uppercase text-white">
          <ArrowLeft size={16} />
          Home
        </a>
        <span className="font-mono text-xs uppercase text-signal">{eyebrow}</span>
        <span className="hidden font-mono text-xs uppercase text-white/35 sm:inline">/ live notes</span>
      </nav>
      <div className="relative z-10 mx-auto max-w-7xl">{children}</div>
    </div>
  );
}

function EmptyState({ title, body }: { title: string; body?: string }) {
  return (
    <div className="rounded-lg border border-white/10 bg-white/[0.045] p-8 text-center backdrop-blur-xl">
      <FileText className="mx-auto text-signal" size={34} />
      <h2 className="mt-4 text-2xl font-semibold text-white">{title}</h2>
      {body ? <p className="mx-auto mt-3 max-w-xl leading-7 text-haze">{body}</p> : null}
    </div>
  );
}

function LoadingPanel({ label = "Loading signal..." }: { label?: string }) {
  return (
    <div className="flex min-h-[45vh] items-center justify-center">
      <div className="inline-flex items-center gap-3 rounded-lg border border-white/10 bg-white/[0.045] px-4 py-3 font-mono text-xs uppercase text-signal">
        <Loader2 className="animate-spin" size={16} />
        {label}
      </div>
    </div>
  );
}

export function BlogIndexPage() {
  const [posts, setPosts] = useState<BlogPost[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [activeTag, setActiveTag] = useState("all");

  useEffect(() => {
    let active = true;

    fetch("/api/posts")
      .then((response) => readJson<{ posts: BlogPost[] }>(response))
      .then((data) => {
        if (active) setPosts(data.posts);
      })
      .catch((requestError: Error) => {
        if (active) setError(requestError.message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  const tags = useMemo(() => {
    const values = new Set<string>();
    posts.forEach((post) => post.tags.forEach((tag) => values.add(tag)));
    return ["all", ...Array.from(values).sort()];
  }, [posts]);

  const filteredPosts = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    return posts.filter((post) => {
      const tagMatches = activeTag === "all" || post.tags.includes(activeTag);
      const queryMatches =
        !normalizedQuery ||
        post.title.toLowerCase().includes(normalizedQuery) ||
        post.summary.toLowerCase().includes(normalizedQuery) ||
        post.tags.join(" ").toLowerCase().includes(normalizedQuery);

      return tagMatches && queryMatches;
    });
  }, [activeTag, posts, query]);

  return (
    <BlogChrome>
      <header className="py-16 md:py-24">
        <motion.p initial="hidden" animate="visible" variants={fadeUp} className="font-mono text-xs uppercase text-signal">
          Threat notes / build logs / security engineering
        </motion.p>
        <motion.h1 initial="hidden" animate="visible" variants={fadeUp} transition={{ delay: 0.06 }} className="micro-glitch-heading mt-4 max-w-4xl text-5xl font-semibold leading-tight text-white md:text-7xl" data-text="Security field notes.">
          Security field notes.
        </motion.h1>
        <motion.p initial="hidden" animate="visible" variants={fadeUp} transition={{ delay: 0.12 }} className="mt-6 max-w-3xl text-lg leading-8 text-haze">
          A curated stream of penetration testing lessons, defensive engineering notes, SIEM visibility ideas, and vulnerability management writeups.
        </motion.p>
      </header>

      <div className="mb-8 grid items-center gap-5 rounded-lg border border-white/10 bg-white/[0.04] p-5 backdrop-blur-xl md:grid-cols-[minmax(0,1fr)_auto]">
        <label className="relative">
          <Search className="pointer-events-none absolute left-5 top-1/2 -translate-y-1/2 text-haze" size={18} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} className="terminal-input !pl-14" placeholder="Search posts, tags, or topics..." />
        </label>
        <div className="flex flex-wrap gap-2 md:justify-end">
          {tags.map((tag) => (
            <button key={tag} type="button" onClick={() => setActiveTag(tag)} className={`min-h-12 rounded-md border px-4 py-2 text-sm transition ${activeTag === tag ? "border-signal bg-signal text-obsidian" : "border-white/10 bg-white/5 text-haze hover:border-signal/40 hover:text-white"}`}>
              {tag === "all" ? "All" : tag}
            </button>
          ))}
        </div>
      </div>

      {loading && <LoadingPanel />}
      {error && <EmptyState title="Blog API not configured yet." body={error} />}
      {!loading && !error && filteredPosts.length === 0 && <EmptyState title="No posts published yet." />}

      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
        {filteredPosts.map((post, index) => (
          <motion.a
            key={post.id}
            href={`/blog/${post.slug}`}
            initial={{ opacity: 0, y: 24 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-70px" }}
            transition={{ duration: 0.45, delay: index * 0.04 }}
            className="group overflow-hidden rounded-lg border border-white/10 bg-white/[0.045] backdrop-blur-xl transition hover:-translate-y-1 hover:border-signal/45 hover:bg-white/[0.07]"
          >
            <div className="relative aspect-[16/9] overflow-hidden bg-radial-signal">
              {post.cover_image_url ? <img src={post.cover_image_url} alt="" className="h-full w-full object-cover opacity-90 transition duration-500 group-hover:scale-105" /> : null}
              <div className="absolute inset-0 bg-gradient-to-t from-obsidian via-transparent to-transparent" />
            </div>
            <div className="p-5">
              <div className="mb-4 flex flex-wrap items-center gap-3 font-mono text-xs uppercase text-haze">
                <span className="inline-flex items-center gap-2 text-signal">
                  <CalendarDays size={14} />
                  {formatDate(post.published_at)}
                </span>
                {post.tags.slice(0, 2).map((tag) => (
                  <span key={tag} className="rounded-md border border-white/10 px-2 py-1">{tag}</span>
                ))}
              </div>
              <h2 className="text-2xl font-semibold leading-tight text-white">{post.title}</h2>
              <p className="mt-4 leading-7 text-haze">{post.summary}</p>
            </div>
          </motion.a>
        ))}
      </div>
    </BlogChrome>
  );
}

function MarkdownView({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      rehypePlugins={[rehypeSanitize]}
      components={{
        h1: ({ children }) => <h1 className="mt-10 text-4xl font-semibold text-white">{children}</h1>,
        h2: ({ children }) => <h2 className="mt-10 text-3xl font-semibold text-white">{children}</h2>,
        h3: ({ children }) => <h3 className="mt-8 text-2xl font-semibold text-white">{children}</h3>,
        p: ({ children }) => <p className="mt-5 leading-8 text-haze">{children}</p>,
        a: ({ children, href }) => <a href={href} className="text-signal underline decoration-signal/40 underline-offset-4 hover:text-white" target={href?.startsWith("http") ? "_blank" : undefined} rel={href?.startsWith("http") ? "noreferrer" : undefined}>{children}</a>,
        ul: ({ children }) => <ul className="mt-5 grid gap-3 pl-5 text-haze">{children}</ul>,
        ol: ({ children }) => <ol className="mt-5 grid list-decimal gap-3 pl-5 text-haze">{children}</ol>,
        li: ({ children }) => <li className="leading-8">{children}</li>,
        blockquote: ({ children }) => <blockquote className="mt-6 border-l-2 border-signal bg-signal/10 px-5 py-3 text-haze">{children}</blockquote>,
        code: ({ inline, className, children, ...props }: any) =>
          inline ? (
            <code className="rounded bg-white/10 px-1.5 py-0.5 font-mono text-sm text-signal" {...props}>{children}</code>
          ) : (
            <code className={`${className || ""} block overflow-x-auto rounded-lg border border-white/10 bg-black/45 p-4 font-mono text-sm leading-7 text-haze`} {...props}>{children}</code>
          ),
        pre: ({ children }) => <pre className="mt-6 overflow-x-auto">{children}</pre>,
        img: ({ src, alt }) => <img src={src || ""} alt={alt || ""} className="mt-8 rounded-lg border border-white/10 shadow-glow" />,
        table: ({ children }) => <div className="mt-6 overflow-x-auto rounded-lg border border-white/10"><table className="w-full border-collapse text-left text-sm text-haze">{children}</table></div>,
        th: ({ children }) => <th className="border-b border-white/10 bg-white/5 px-4 py-3 text-white">{children}</th>,
        td: ({ children }) => <td className="border-b border-white/10 px-4 py-3">{children}</td>,
      }}
    >
      {content}
    </ReactMarkdown>
  );
}

export function BlogPostPage({ slug }: { slug: string }) {
  const [post, setPost] = useState<BlogPost | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;

    fetch(`/api/posts/${encodeURIComponent(slug)}`)
      .then((response) => readJson<{ post: BlogPost }>(response))
      .then((data) => {
        if (active) setPost(data.post);
      })
      .catch((requestError: Error) => {
        if (active) setError(requestError.message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [slug]);

  if (loading) {
    return (
      <BlogChrome>
        <LoadingPanel label="Loading post..." />
      </BlogChrome>
    );
  }

  if (error || !post) {
    return (
      <BlogChrome>
        <div className="py-24">
          <EmptyState title="Post not found." body="This field note is not published, has moved, or the blog database has not been configured yet." />
        </div>
      </BlogChrome>
    );
  }

  return (
    <BlogChrome>
      <article className="py-14 md:py-20">
        <a href="/blog" className="inline-flex items-center gap-2 text-sm text-haze transition hover:text-white">
          <ArrowLeft size={16} />
          Back to blog
        </a>
        <header className="mt-8 max-w-4xl">
          <div className="flex flex-wrap items-center gap-3 font-mono text-xs uppercase text-signal">
            <CalendarDays size={15} />
            {formatDate(post.published_at)}
            {post.tags.map((tag) => (
              <span key={tag} className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-haze">{tag}</span>
            ))}
          </div>
          <h1 className="micro-glitch-heading mt-5 text-5xl font-semibold leading-tight text-white md:text-7xl" data-text={post.title}>{post.title}</h1>
          <p className="mt-6 text-xl leading-8 text-haze">{post.summary}</p>
        </header>
        {post.cover_image_url ? <img src={post.cover_image_url} alt="" className="mt-10 aspect-[21/9] w-full rounded-lg border border-white/10 object-cover shadow-glow" /> : null}
        <div className="mx-auto mt-12 max-w-4xl">
          <MarkdownView content={post.content_md} />
        </div>
      </article>
    </BlogChrome>
  );
}

function formFromPost(post: BlogPost): EditorForm {
  return {
    id: post.id,
    slug: post.slug,
    title: post.title,
    summary: post.summary,
    content_md: post.content_md,
    cover_image_key: post.cover_image_key,
    tags: post.tags.join(", "),
    status: post.status,
  };
}

export function AdminPage({ path }: { path: string }) {
  const [posts, setPosts] = useState<BlogPost[]>([]);
  const [form, setForm] = useState<EditorForm>(blankPost);
  const [mode, setMode] = useState<"list" | "edit">("list");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  const navigate = (nextPath: string) => {
    window.history.pushState({}, "", nextPath);
    window.dispatchEvent(new PopStateEvent("popstate"));
  };

  const loadPosts = async () => {
    setLoading(true);
    setError("");

    try {
      const data = await fetch("/api/admin/posts").then((response) => readJson<{ posts: BlogPost[] }>(response));
      setPosts(data.posts);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Admin request failed");
    } finally {
      setLoading(false);
    }
  };

  const loadPost = async (id: string) => {
    setLoading(true);
    setError("");

    try {
      const data = await fetch(`/api/admin/posts/${encodeURIComponent(id)}`).then((response) => readJson<{ post: BlogPost }>(response));
      setForm(formFromPost(data.post));
      setMode("edit");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load post");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const editMatch = path.match(/^\/admin\/posts\/([^/]+)\/edit\/?$/);

    if (path === "/admin/posts/new") {
      setForm(blankPost);
      setMode("edit");
      setLoading(false);
      return;
    }

    if (editMatch) {
      loadPost(decodeURIComponent(editMatch[1]));
      return;
    }

    setMode("list");
    loadPosts();
  }, [path]);

  const updateForm = (field: keyof EditorForm, value: string | null) => {
    setForm((current) => ({
      ...current,
      [field]: value,
      slug: field === "title" && !current.id && !current.slug ? slugify(String(value || "")) : current.slug,
    }));
  };

  const savePost = async (nextStatus?: PostStatus) => {
    setSaving(true);
    setMessage("");
    setError("");

    const payload = {
      slug: form.slug || slugify(form.title),
      title: form.title,
      summary: form.summary,
      content_md: form.content_md,
      cover_image_key: form.cover_image_key,
      tags: form.tags.split(",").map((tag) => tag.trim()).filter(Boolean),
      status: nextStatus || form.status,
    };

    try {
      const response = await fetch(form.id ? `/api/admin/posts/${encodeURIComponent(form.id)}` : "/api/admin/posts", {
        method: form.id ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await readJson<{ post: BlogPost }>(response);
      setForm(formFromPost(data.post));
      setMessage(nextStatus === "published" ? "Post published." : "Post saved.");
      navigate(`/admin/posts/${data.post.id}/edit`);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to save post");
    } finally {
      setSaving(false);
    }
  };

  const deletePost = async (id: string) => {
    if (!window.confirm("Delete this post permanently?")) return;

    setSaving(true);
    setError("");

    try {
      await fetch(`/api/admin/posts/${encodeURIComponent(id)}`, { method: "DELETE" }).then((response) => readJson<{ success: boolean }>(response));
      setMessage("Post deleted.");
      navigate("/admin");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to delete post");
    } finally {
      setSaving(false);
    }
  };

  const uploadImage = async (file: File) => {
    const uploadForm = new FormData();
    uploadForm.append("image", file);

    const data = await fetch("/api/admin/upload", {
      method: "POST",
      body: uploadForm,
    }).then((response) => readJson<{ key: string; url: string }>(response));

    return data;
  };

  const handleCoverUpload = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setSaving(true);
    setError("");

    try {
      const image = await uploadImage(file);
      updateForm("cover_image_key", image.key);
      setMessage("Cover image uploaded.");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Upload failed");
    } finally {
      setSaving(false);
      event.target.value = "";
    }
  };

  const handleInlineUpload = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setSaving(true);
    setError("");

    try {
      const image = await uploadImage(file);
      const markdownImage = `\n\n![${file.name.replace(/\.[^.]+$/, "")}](${image.url})\n\n`;
      const textarea = textareaRef.current;
      const start = textarea?.selectionStart ?? form.content_md.length;
      const end = textarea?.selectionEnd ?? form.content_md.length;
      updateForm("content_md", `${form.content_md.slice(0, start)}${markdownImage}${form.content_md.slice(end)}`);
      setMessage("Inline image inserted.");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Upload failed");
    } finally {
      setSaving(false);
      event.target.value = "";
    }
  };

  return (
    <BlogChrome eyebrow="Admin / Cloudflare Access protected">
      <div className="py-12 md:py-16">
        <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="font-mono text-xs uppercase text-signal">Publishing console</p>
            <h1 className="mt-3 text-4xl font-semibold text-white md:text-6xl">Blog control panel.</h1>
            <p className="mt-4 max-w-2xl leading-8 text-haze">Create Markdown drafts, upload images to R2, preview posts, and publish directly from Cloudflare.</p>
          </div>
          <button type="button" onClick={() => navigate("/admin/posts/new")} className="inline-flex h-12 items-center justify-center gap-2 rounded-lg bg-signal px-5 text-sm font-semibold text-obsidian transition hover:bg-white">
            <Plus size={17} />
            New Post
          </button>
        </div>

        {error && (
          <div className="mb-5 rounded-lg border border-trace/40 bg-trace/10 p-4 text-sm leading-6 text-trace">
            <div className="flex items-center gap-2 font-semibold">
              <Lock size={16} />
              {error}
            </div>
            <p className="mt-2 text-haze">If this is an auth error, configure Cloudflare Access for /admin* and bind ADMIN_EMAIL.</p>
          </div>
        )}
        {message && <div className="mb-5 rounded-lg border border-signal/30 bg-signal/10 p-4 font-mono text-xs uppercase text-signal">{message}</div>}

        {loading && <LoadingPanel label="Loading admin..." />}

        {!loading && mode === "list" && (
          <div className="grid gap-4">
            {posts.length === 0 && <EmptyState title="No posts yet." body="Create your first draft, upload a cover image, and publish it when it is ready." />}
            {posts.map((post) => (
              <article key={post.id} className="grid gap-4 rounded-lg border border-white/10 bg-white/[0.045] p-5 backdrop-blur-xl md:grid-cols-[1fr_auto] md:items-center">
                <div>
                  <div className="mb-3 flex flex-wrap items-center gap-2 font-mono text-xs uppercase">
                    <span className={post.status === "published" ? "text-signal" : "text-volt"}>{post.status}</span>
                    <span className="text-haze">{formatDate(post.published_at || post.updated_at)}</span>
                    {post.tags.map((tag) => <span key={tag} className="rounded-md border border-white/10 px-2 py-1 text-haze">{tag}</span>)}
                  </div>
                  <h2 className="text-2xl font-semibold text-white">{post.title}</h2>
                  <p className="mt-2 leading-7 text-haze">{post.summary}</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {post.status === "published" && <a href={`/blog/${post.slug}`} className="inline-flex h-10 items-center gap-2 rounded-md border border-white/10 px-3 text-sm text-haze transition hover:text-white"><Eye size={15} /> View</a>}
                  <button type="button" onClick={() => navigate(`/admin/posts/${post.id}/edit`)} className="inline-flex h-10 items-center gap-2 rounded-md border border-signal/30 bg-signal/10 px-3 text-sm text-signal transition hover:bg-signal hover:text-obsidian">
                    Edit
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}

        {!loading && mode === "edit" && (
          <form onSubmit={(event: FormEvent) => { event.preventDefault(); savePost(); }} className="grid gap-5 xl:grid-cols-[1fr_0.9fr]">
            <section className="rounded-lg border border-white/10 bg-white/[0.045] p-5 backdrop-blur-xl">
              <div className="grid gap-4">
                <label className="grid gap-2">
                  <span className="font-mono text-xs uppercase text-signal">Title</span>
                  <input value={form.title} onChange={(event) => updateForm("title", event.target.value)} className="terminal-input" placeholder="Post title" required />
                </label>
                <div className="grid gap-4 md:grid-cols-2">
                  <label className="grid gap-2">
                    <span className="font-mono text-xs uppercase text-signal">Slug</span>
                    <input value={form.slug} onChange={(event) => updateForm("slug", slugify(event.target.value))} className="terminal-input" placeholder="post-slug" required />
                  </label>
                  <label className="grid gap-2">
                    <span className="font-mono text-xs uppercase text-signal">Tags</span>
                    <input value={form.tags} onChange={(event) => updateForm("tags", event.target.value)} className="terminal-input" placeholder="Tag one, Tag two" />
                  </label>
                </div>
                <label className="grid gap-2">
                  <span className="font-mono text-xs uppercase text-signal">Summary</span>
                  <textarea value={form.summary} onChange={(event) => updateForm("summary", event.target.value)} className="terminal-input min-h-24 resize-y" placeholder="Short public summary" required />
                </label>
                <div className="grid gap-3 rounded-lg border border-white/10 bg-black/20 p-4">
                  <div className="flex flex-wrap gap-3">
                    <label className="inline-flex h-11 cursor-pointer items-center gap-2 rounded-md border border-white/10 bg-white/5 px-3 text-sm text-haze transition hover:border-signal/40 hover:text-white">
                      <UploadCloud size={16} />
                      Upload cover
                      <input type="file" accept="image/png,image/jpeg,image/webp,image/gif" className="hidden" onChange={handleCoverUpload} />
                    </label>
                    <label className="inline-flex h-11 cursor-pointer items-center gap-2 rounded-md border border-white/10 bg-white/5 px-3 text-sm text-haze transition hover:border-signal/40 hover:text-white">
                      <ImagePlus size={16} />
                      Insert inline image
                      <input type="file" accept="image/png,image/jpeg,image/webp,image/gif" className="hidden" onChange={handleInlineUpload} />
                    </label>
                  </div>
                  {form.cover_image_key && <img src={mediaUrl(form.cover_image_key) || ""} alt="" className="aspect-[16/7] w-full rounded-lg border border-white/10 object-cover" />}
                </div>
                <label className="grid gap-2">
                  <span className="font-mono text-xs uppercase text-signal">Markdown</span>
                  <textarea ref={textareaRef} value={form.content_md} onChange={(event) => updateForm("content_md", event.target.value)} className="terminal-input min-h-[460px] resize-y font-mono text-sm leading-7" required />
                </label>
              </div>
            </section>

            <aside className="grid gap-5">
              <div className="rounded-lg border border-white/10 bg-white/[0.045] p-5 backdrop-blur-xl">
                <div className="mb-4 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                  <Tags size={15} />
                  Publish controls
                </div>
                <div className="grid gap-3">
                  <button type="submit" disabled={saving} className="inline-flex h-12 items-center justify-center gap-2 rounded-lg border border-white/10 bg-white/5 px-5 text-sm font-semibold text-white transition hover:border-signal/40 disabled:opacity-60">
                    <Save size={17} />
                    Save Draft
                  </button>
                  <button type="button" disabled={saving} onClick={() => savePost("published")} className="inline-flex h-12 items-center justify-center gap-2 rounded-lg bg-signal px-5 text-sm font-semibold text-obsidian transition hover:bg-white disabled:opacity-60">
                    <Send size={17} />
                    Publish
                  </button>
                  {form.id && (
                    <>
                      <button type="button" disabled={saving} onClick={() => savePost("draft")} className="inline-flex h-12 items-center justify-center gap-2 rounded-lg border border-volt/30 bg-volt/10 px-5 text-sm font-semibold text-volt transition hover:bg-volt hover:text-obsidian disabled:opacity-60">
                        Unpublish
                      </button>
                      <button type="button" disabled={saving} onClick={() => deletePost(form.id!)} className="inline-flex h-12 items-center justify-center gap-2 rounded-lg border border-trace/35 bg-trace/10 px-5 text-sm font-semibold text-trace transition hover:bg-trace hover:text-white disabled:opacity-60">
                        <Trash2 size={17} />
                        Delete
                      </button>
                    </>
                  )}
                </div>
              </div>
              <div className="rounded-lg border border-white/10 bg-white/[0.045] p-5 backdrop-blur-xl">
                <div className="mb-4 flex items-center gap-2 font-mono text-xs uppercase text-signal">
                  <Eye size={15} />
                  Live preview
                </div>
                <h2 className="text-3xl font-semibold text-white">{form.title || "Untitled post"}</h2>
                <p className="mt-3 leading-7 text-haze">{form.summary || "Summary preview appears here."}</p>
                <div className="mt-6 max-h-[620px] overflow-auto rounded-lg border border-white/10 bg-black/25 p-4">
                  <MarkdownView content={form.content_md} />
                </div>
              </div>
            </aside>
          </form>
        )}
      </div>
    </BlogChrome>
  );
}
