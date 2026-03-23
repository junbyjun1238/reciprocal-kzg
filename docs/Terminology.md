## Disambiguation of "Native"

In cryptographic proof systems, the term "native" can have multiple interpretations depending on the specific context of discussion.

### Context 1: Native vs Emulated

When referring to "native field / curve" and "emulated (non-native) field / curve," "native" denotes that the field or curve can be directly represented within the arithmetic circuit of the proof system.
More specifically, "native" in native field means that the field is the same as the circuit's constraint field (i.e., the field over which the circuit is defined).
Similarly, a "native" curve is one whose base field (i.e., the field over which the curve is defined, which is also the field that a point's coordinates belong to) matches the circuit's constraint field.

In contrast, "emulated" or "non-native" fields and curves are those that cannot be directly represented in the circuit's constraint field and thus require special handling (a.k.a. emulation) within the circuit.

> [!TIP]
> A side note irrelevant to the main discussion is that the boundary between "native" and "emulated" is not very clear-cut.
>
> For instance, as long as the foundamental element of the circuit is not a curve point (which is the case for all current constraint systems), even a native curve is "emulated" in some sense because curve points need to be encoded as multiple elements in the constraint field and curve operations need to be broken down into field operations.
> One can further argue that, if we regard such an "emulation" as a native representation of the curve, then why not also consider emulated fields as native as well, since they are also encoded as multiple elements in the constraint field.
>
> In Sonobe, we distinguish "native" and "emulated" based on whether the in-circuit representation is the preferred or most efficient form for the given field or curve. For a field element, the preferred representation is a single element in the constraint field, while for a curve point, it is a tuple of elements in the constraint field representing the coordinates, but each coordinate itself is not further decomposed. Consequently, if the circuit is able to achieve these preferred representations, we classify the field or curve as "native"; otherwise, it is deemed "emulated."

### Context 2: Native vs In-Circuit

Another common usage of "native" is to distinguish between values and operations built in the host programming language (e.g., Rust) and those defined in the arithmetic circuit of the proof system. In the former case, we refer to them as "native"/"out-of-circuit", while in the latter case, we call them "in-circuit".

### Proposed New Terminology

It is unlikely for experienced practitioners to confuse the two contexts above when "native" is used, as the context usually makes it clear which meaning is intended.
However, to ensure everyone is on the same page and to avoid any potential mental overhead in interpreting "native" correctly, we propose adopting more specific terminology for each context.

- For Context 1, prefer <u>_Canonical_</u> vs <u>_Emulated_</u>.

  **Justification**: _Canonical_ is not a standard term in the literature and is coined for use in Sonobe. However, it intuitively conveys the idea of being the standard or preferred representation within the circuit.
- For Context 2:
    - When referring to something that holds data:
        - Prefer <u>_Value_</u> vs <u>_Variable_</u>. Further qualify them as _Out-of-Circuit Value_ and _In-Circuit Variable_ if necessary.
        - Neutral terms such as _Data_, _Element_, _Key_, _Instance_, _Witness_, etc., are also acceptable when solely focusing on the in-circuit or out-of-circuit context.
      
        **Justification**: The use of _Value_ and _Variable_ aligns with existing conventions, as these terms are widely used in the arkworks codebase.
    - When referring to something that performs computation:
        - Prefer <u>_Widget_</u> vs <u>_Gadget_</u>. Further qualify them as _Out-of-Circuit Widget_ and _In-Circuit Gadget_ if necessary.
        - Neutral terms such as _Algorithm_, _Procedure_, _Function_, _Method_, etc., are also acceptable when solely focusing on the in-circuit or out-of-circuit context.
      
      **Justification**: _Gadget_ is already a standard term for in-circuit computation modules or utilities.
      
      _Widget_ is invented by us to suggest a computational component that operates outside the circuit while maintaining a consistent and visually / phonetically appealing naming scheme.
      
      Furthermore, searching for "widget vs gadget" yields results that align with our intended meanings. For instance, [this article](https://www.thoughtco.com/widget-vs-gadget-3486689) suggests that in web development, "widgets work on multiple platforms, but gadgets are usually limited to specific devices or systems." This distinction resonates with our usage, where widgets operate in the general-purpose host environment, while gadgets are specialized for the circuit environment.

The proposed terminology is used throughout the Sonobe documentation and codebase.
For contributions, we recommend doing so as well to enhance clarity and reduce ambiguity. However, in casual discussions / issue reports, it is fine to use "native" for both contexts.