D("foo.com", "none",
    CAA_BUILDER({
        label: "@",
        iodef: "mailto:caa@foo.com",
        iodef_critical: true,
        issue: ["letsencrypt.org", "comodoca.com"],
        issuewild: "none",
    })
);
