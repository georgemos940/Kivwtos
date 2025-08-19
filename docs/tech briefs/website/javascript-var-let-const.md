# Var, Let, Const – Differences in JavaScript


---
# 1. Scope

- **var** → function-scoped or global-scoped
- **let** → block-scoped (lives only inside `{}`)    
- **const** → block-scoped


Example:
```javascript
if (true) {
  var x = 1;   // available outside too
  let y = 2;   // only inside this block
  const z = 3; // only inside this block
}
console.log(x); // 1
console.log(y); // Error
console.log(z); // Error

```

---
## 2. Hoisting

- **var** → hoisted and initialized as `undefined`
- **let/const** → hoisted but NOT initialized → _Temporal Dead Zone (TDZ)_


Example:
```javascript
console.log(a); // undefined
var a = 5;

console.log(b); // ReferenceError (TDZ)
let b = 10;

console.log(c); // ReferenceError (TDZ)
const c = 15;

```

---
## 3. Redeclaration & Reassignment

- **var** → can be redeclared and reassigned
- **let** → can be reassigned, but NOT redeclared in the same scope    
- **const** → cannot be reassigned, cannot be redeclared (must be initialized at declaration)

Example:
```javascript
var a = 1;
var a = 2;   // ok
a = 3;       // ok

let b = 1;
b = 2;       // ok
let b = 3;   // Error: redeclaration

const c = 1;
c = 2;       // Error: reassignment
const c = 3; // Error: redeclaration

```

---
# 4. Objects and Arrays with Const

- `const` only protects the _reference_, not the contents.
- You cannot reassign the whole object/array, but you can change its properties/items.

Example:
```javascript
const obj = { name: "John" };
obj.name = "Jane"; // ✅ allowed
obj = { age: 30 }; // ❌ Error

```

---

## 5. Loops

- **var** → uses the _same_ variable for every iteration (can cause bugs with async code)
- **let** → creates a _new_ variable binding for each iteration

Example:
```javascript
for (var i = 0; i < 3; i++) {
  setTimeout(() => console.log("var", i), 100);
}
// prints: var 3, var 3, var 3

for (let j = 0; j < 3; j++) {
  setTimeout(() => console.log("let", j), 100);
}
// prints: let 0, let 1, let 2

```


---
## Quick Summary

- **var** → function/global scope, redeclare & reassign, hoisted as `undefined`    
- **let** → block scope, reassign only, TDZ error if used before declaration
- **const** → block scope, no redeclare, no reassign, must initialize