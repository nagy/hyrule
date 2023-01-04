(require
  hyrule.anaphoric [ap-map]
  hyrule.control [case]
  hyrule.macrotools [defmacro/g! defmacro!])

(defn pipe-as-json [arg #* rest]
  (import json io)
  (cond
    (isinstance arg io.IOBase) (json.load arg)
    (isinstance arg str) (json.load (open arg))
    True (json.dumps arg)))

(defn pipe-as-lines [arg #* rest]
  (gfor line (open arg) line))

(defn pipe-as-url [url]
  (import io requests)
  (io.BytesIO
    (.
      (requests.get url)
      content)))

(setv pipereg { })
(defmacro register-pipe-part [args #* body]
  `(eval-when-compile
    (import hyrule)
    (setv (get hyrule.control.pipereg :limit)
       (fn ~args ~@body))))

(defmacro pipe [argname #* body]
  `(do
     (eval-when-compile (import hyrule.control))
     (import sys os io json zipfile
             pprint
             itertools
             itertools [chain])
     (setv _input_format
           (match (os.path.splitext (os.readlink "/proc/self/fd/0"))
                  [root ext] (cut ext 1 None)))
     (setv _output_format
           (or (.get os.environ "PIPEPRINT" None)
               (match (os.path.splitext (os.readlink "/proc/self/fd/1"))
                      [root ext] (cut ext 1 None))))
     (as-> None ~argname
           (case _input_format
                 "yaml" (do (import yaml) (yaml.safe_load sys.stdin))
                 "json" (json.load sys.stdin)
                 "toml" (do (import tomllib) (tomllib.load sys.stdin))
                 "pcap" (do (import scapy.all [rdpcap]) (rdpcap sys.stdin.buffer))
                 else ~argname)
           ~@(ap-map
               (let [rest  (cut it 1 None)]
                 (case (get it 0)
                       :json    `(hyrule.control.pipe-as-json ~@rest ~argname)
                       :chain   `(itertools.chain ~argname ~@rest)
                       :flatten `(itertools.chain.from_iterable ~argname)
                       :lines   `(hyrule.control.pipe-as-lines ~@rest ~argname)
                       :limit   `(itertools.islice ~argname ~@rest)
                       :for     `(lfor it ~argname ~@rest)
                       :map     `(ap-map    (do ~@rest) ~argname)
                       :filter  `(ap-filter (do ~@rest) ~argname)
                       :reduce  `(ap-reduce (do ~@rest) ~argname)
                       :map-url `(ap-map (hyrule.control.pipe-as-url it) ~argname)
                       :limit   ((get pipereg :limit) rest)
                       else it))
               body)
           (case _output_format
                 "yaml" (do
                          (import yaml)
                          (try
                            (print (yaml.safe_dump ~argname) :end "")
                            (except [yaml.representer.RepresenterError]
                              (print (yaml.safe_dump (ap-lfor ~argname it)) :end ""))))
                 "json" (try
                          (print (json.dumps ~argname))
                          (except [TypeError]
                            (print (json.dumps (ap-lfor ~argname it)))))
                 "len" (print (len ~argname))
                 "pcap" (do (import scapy.all [wrpcap])
                            (wrpcap sys.stdout.buffer ~argname))
                 "collect" (pprint.pprint (ap-lfor ~argname it))
                 else (do (pprint.pprint ~argname) ~argname)))))


(defmacro defmain/pipe [args #* body]
  ;; cannot use defmain because it lacks module support
  `(do
     (defn main ~args
       (pipe ~@body))
     (when (= __name__ "__main__")
       (main))))
