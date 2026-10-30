package main

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "os"
    "time"
    bolt "go.etcd.io/bbolt"
)

type Summary struct {
    NamespaceCount int `json:"namespace_count"`
    MobyPresent bool `json:"moby_present"`
    Containers int `json:"containers"`
    Images int `json:"images"`
    SnapshotReferences int `json:"snapshot_references"`
    ContentBlobs int `json:"content_blobs"`
    ContainerHashes []string `json:"container_id_hashes"`
}
func buckets(b *bolt.Bucket) int {
    count := 0
    if b != nil { b.ForEach(func(k,v []byte) error { if v == nil { count++ }; return nil }) }
    return count
}
func main() {
    if len(os.Args) != 2 { os.Exit(2) }
    db, err := bolt.Open(os.Args[1],0600,&bolt.Options{ReadOnly:true,Timeout:time.Second})
    if err != nil { os.Exit(3) }
    defer db.Close()
    out := Summary{ContainerHashes:[]string{}}
    err = db.View(func(tx *bolt.Tx) error {
        version := tx.Bucket([]byte("v1"))
        if version == nil { os.Exit(4) }
        return version.ForEach(func(name,value []byte) error {
            if value != nil { return nil }
            out.NamespaceCount++
            if string(name) != "moby" { return nil }
            out.MobyPresent = true
            ns := version.Bucket(name)
            containers := ns.Bucket([]byte("containers"))
            out.Containers = buckets(containers)
            if containers != nil {
                containers.ForEach(func(key,value []byte) error {
                    if value == nil { h:=sha256.Sum256(key);out.ContainerHashes=append(out.ContainerHashes,hex.EncodeToString(h[:])) };return nil
                })
            }
            out.Images = buckets(ns.Bucket([]byte("images")))
            content := ns.Bucket([]byte("content"))
            if content != nil { out.ContentBlobs=buckets(content.Bucket([]byte("blob"))) }
            snapshots:=ns.Bucket([]byte("snapshots"))
            if snapshots != nil { snapshots.ForEach(func(key,value []byte) error {
                if value == nil { out.SnapshotReferences+=buckets(snapshots.Bucket(key)) };return nil
            }) }
            return nil
        })
    })
    if err != nil { os.Exit(5) }
    json.NewEncoder(os.Stdout).Encode(out)
}
