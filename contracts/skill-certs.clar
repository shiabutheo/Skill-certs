;; ------------------------------------------------
;; Contract: skill-certs
;; SkillCerts - On-chain skill/license certification (soulbound)
;; ------------------------------------------------

(define-constant ERR_NOT_ADMIN (err u100))
(define-constant ERR_NOT_APPROVED_ISSUER (err u101))
(define-constant ERR_CERT_NOT_FOUND (err u102))
(define-constant ERR_ALREADY_ISSUED (err u103))
(define-constant ERR_NOT_ISSUER (err u104))
(define-constant ERR_ALREADY_REVOKED (err u105))

;; Contract admin (initial admin is deployer)
(define-data-var contract-admin principal tx-sender)

;; Approved issuers map: issuer principal -> approved bool
(define-map issuers
  { issuer: principal }
  { approved: bool })

;; Certificate record (soulbound)
;; key: id:uint
(define-map certificates
  { id: uint }
  { recipient: principal,
    issuer: principal,
    title: (string-ascii 100),
    metadata: (string-ascii 200),
    issued-at: uint,      ;; block-height at issuance
    expires-at: (optional uint), ;; optional block-height expiry
    revoked: bool })

(define-data-var cert-counter uint u0)

;; ------------------------------
;; Admin functions
;; ------------------------------

;; Change admin (transfer adminship)
(define-public (set-admin (new-admin principal))
  (if (is-eq tx-sender (var-get contract-admin))
      (begin
        (var-set contract-admin new-admin)
        (ok true))
      ERR_NOT_ADMIN))

;; Approve an issuer
(define-public (approve-issuer (issuer principal))
  (if (is-eq tx-sender (var-get contract-admin))
      (begin
        (map-set issuers { issuer: issuer } { approved: true })
        (ok true))
      ERR_NOT_ADMIN))

;; Revoke issuer approval
(define-public (revoke-issuer (issuer principal))
  (if (is-eq tx-sender (var-get contract-admin))
      (begin
        (map-set issuers { issuer: issuer } { approved: false })
        (ok true))
      ERR_NOT_ADMIN))

;; ------------------------------
;; Issuer / Certificate functions
;; ------------------------------

;; Internal helper: check issuer approved
(define-read-only (is-approved-issuer (maybe-issuer principal))
  (match (map-get? issuers { issuer: maybe-issuer })
    inst (ok (get approved inst))
    (ok false)))

;; Issue a certificate (only approved issuer)
(define-public (issue-cert (recipient principal) (title (string-ascii 100))
                           (metadata (string-ascii 200)) (expires-at (optional uint)))
  (let ((inst (map-get? issuers { issuer: tx-sender })))
    (if (and (is-some inst) (get approved (unwrap! inst ERR_NOT_APPROVED_ISSUER)))
        (begin
          (var-set cert-counter (+ (var-get cert-counter) u1))
          (map-set certificates { id: (var-get cert-counter) }
            { recipient: recipient,
              issuer: tx-sender,
              title: title,
              metadata: metadata,
              issued-at: stacks-block-height,
              expires-at: expires-at,
              revoked: false })
          (ok (var-get cert-counter)))
        ERR_NOT_APPROVED_ISSUER)))

;; Revoke a certificate (only the original issuer)
(define-public (revoke-cert (cert-id uint))
  (match (map-get? certificates { id: cert-id })
    cert
      (if (is-eq tx-sender (get issuer cert))
          (if (get revoked cert)
              ERR_ALREADY_REVOKED
              (begin
                (map-set certificates { id: cert-id }
                  { recipient: (get recipient cert),
                    issuer: (get issuer cert),
                    title: (get title cert),
                    metadata: (get metadata cert),
                    issued-at: (get issued-at cert),
                    expires-at: (get expires-at cert),
                    revoked: true })
                (ok true)))
          ERR_NOT_ISSUER)
    ERR_CERT_NOT_FOUND))

;; ------------------------------
;; Read-only / verification
;; ------------------------------

;; Get certificate details
(define-read-only (get-cert (cert-id uint))
  (map-get? certificates { id: cert-id }))

;; Verify certificate: returns ok with record if valid (not revoked and not expired)
(define-read-only (verify-cert (cert-id uint))
  (match (map-get? certificates { id: cert-id })
    cert
      (let ((rev (get revoked cert))
            (exp (get expires-at cert)))
        (if rev
            ERR_ALREADY_REVOKED
            (if (is-some exp)
                (if (>= (unwrap-panic exp) stacks-block-height) ;; still valid
                    (ok { recipient: (get recipient cert), issuer: (get issuer cert), title: (get title cert), metadata: (get metadata cert), issued-at: (get issued-at cert), expires-at: exp })
                    ERR_ALREADY_REVOKED) ;; expired considered effectively revoked/invalid
                (ok { recipient: (get recipient cert), issuer: (get issuer cert), title: (get title cert), metadata: (get metadata cert), issued-at: (get issued-at cert), expires-at: none }))))
    ERR_CERT_NOT_FOUND))

;; Check if a principal is an approved issuer
(define-read-only (is-approved (issuer principal))
  (map-get? issuers { issuer: issuer }))
