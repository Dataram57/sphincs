export function merkleRoot<T>(
    Hash: (left: T, right: T, height: number, index: number) => T,
    GetNextMember : (queryIndex : number) => T,
    height: number
) : T {
    //consts
    const maxElements = 1 << height;

    //vars
    const roots: T[] = Array(height + 2);
    let index : number;
    let level : number;

    //for each element
    for (let i = 0; i < maxElements; i++) {
        //get member
        roots[0] = GetNextMember(i);

        //do optimal hashes
        level = 1;
        for (index = i; (index & 1) === 1; index >>= 1, level++) {
            roots[level] = Hash(
                roots[level],
                roots[level - 1],
                level,          // resulting node height
                index >> 1      // resulting node index
            );
        }

        //copy last hash level up
        roots[level] = roots[level - 1];
    }

    //return last hash
    return roots[height + 1];
}


export function merkleTrace<T>(
    Hash : (left : T, right : T, queryIndex : number, nodeIndex : number) => T,
    GetNextSibling : (queryIndex : number) => T,
    start : T,
    authPath : number,
    height : number
) : T{
    //vars
    let root : T = start;
    let sibling : T;

    //trace
    for(let i = 0; i < height; i++){
        //get sibling
        sibling = GetNextSibling(i);

        //Hash
        if(authPath & 1)
            root = Hash(sibling, root, i, authPath)
        else
            root = Hash(root, sibling, i, authPath)

        //next
        //alternative: authPath >>>= 1;
        authPath >>= 1;
    }

    //return root
    return root;
}


export function merkleProof<T>(
    Hash: (left: T, right: T, height: number, index: number) => T,
    GetNextMember: (queryIndex: number) => T,
    leafIndex: number,
    height: number
): { root: T; authPath: T[] } {
    //consts
    const maxElements = 1 << height;
    //vars
    const roots: T[] = Array(height + 2);
    const authPath: T[] = Array(height);
    let index: number;
    let level: number;

    //for each element
    for(let i = 0; i < maxElements; i++){
        //get member
        roots[0] = GetNextMember(i);

        //capture height-0 sibling: leafIndex's neighbor is fetched raw, no hashing needed
        if (i === (leafIndex ^ 1))
            authPath[0] = roots[0];

        //do optimal hashes
        level = 1;
        for (index = i; (index & 1) === 1; index >>= 1, level++) {
            roots[level] = Hash(
                roots[level],
                roots[level - 1],
                level,          // resulting node height
                index >> 1      // resulting node index
            );

            //capture sibling at this height, the moment it's finalized
            if ((index >> 1) === ((leafIndex >> level) ^ 1)) {
                authPath[level] = roots[level];
            }
        }
        //copy last hash level up
        roots[level] = roots[level - 1];
    }

    //return root and its authentication path
    return { 
        root: roots[height + 1],
        authPath
    };
}