D("foo.com", "none",
    SPF_BUILDER({
        label: "@",
        parts: ["v=spf1", "include:_spf.google.com", "-all"],
    })
);
