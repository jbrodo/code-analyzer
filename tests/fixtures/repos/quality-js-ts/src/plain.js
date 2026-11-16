export function route(kind, size, color, shape, weight, label) {
  const leftover = 1;
  if (kind === "a") {
    if (size > 10) {
      if (color === "red") {
        if (shape === "round") {
          if (weight > 5) {
            if (label) {
              return "a-heavy-labelled";
            }
            return "a-heavy";
          }
          return "a-round";
        }
        return "a-red";
      }
      return "a-big";
    }
    return "a";
  } else if (kind === "b") {
    return size > 10 ? "b-big" : "b";
  } else if (kind === "c") {
    return color === "red" ? "c-red" : "c";
  } else if (kind === "d") {
    return shape === "round" ? "d-round" : "d";
  } else if (kind === "e") {
    return weight > 5 ? "e-heavy" : "e";
  } else if (kind === "f") {
    return label ? "f-labelled" : "f";
  } else if (kind === "g") {
    return "g";
  } else if (kind === "h") {
    return "h";
  } else if (kind === "i") {
    return "i";
  } else if (kind === "j") {
    return "j";
  } else if (kind === "k") {
    return "k";
  } else if (kind === "l") {
    return "l";
  } else if (kind === "m") {
    return "m";
  } else if (kind === "n") {
    return "n";
  }
  if (size === size) {
    return "same";
  }
  return "none";
}
