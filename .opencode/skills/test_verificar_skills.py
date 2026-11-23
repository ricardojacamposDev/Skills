"""Testes do verificador de consistência (verificar_skills.py), em árvore fictícia temporária."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("verificar_skills", Path(__file__).resolve().parent / "verificar_skills.py")
vs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vs)

CORPO_CMD = "Faça uma revisão completa deste projeto e relate os problemas por prioridade, explicando de forma simples cada um deles. " * 2


def montar(tmp, skills, readme_skills="", readme_raiz="", comandos=None):
    raiz = Path(tmp)
    for nome, conteudo in skills.items():
        d = raiz / ".opencode/skills" / nome
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(conteudo, encoding="utf-8")
    (raiz / ".opencode/skills/README.md").write_text(readme_skills, encoding="utf-8")
    (raiz / "README.md").write_text(readme_raiz, encoding="utf-8")
    (raiz / ".opencode/commands").mkdir(parents=True)
    for nome, texto in (comandos or {}).items():
        (raiz / ".opencode/commands" / nome).write_text(texto, encoding="utf-8")
    return raiz


def skill(nome, extra=""):
    return f"---\nname: {nome}\ndescription: faz algo útil\n---\n# T\n{extra}\n"


class TesteVerificador(unittest.TestCase):
    def rodar(self, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            return vs.verificar(montar(tmp, **kw))[0]

    def test_conjunto_consistente_nao_tem_problemas(self):
        idx = "| `alfa-um` | `beta-dois` |\n2 skills\n"
        self.assertEqual(self.rodar(skills={"alfa-um": skill("alfa-um", "veja `beta-dois`"), "beta-dois": skill("beta-dois")},
                                    readme_skills=idx, readme_raiz=idx), [])

    def test_name_diferente_do_diretorio(self):
        p = self.rodar(skills={"alfa-um": skill("outro-nome")}, readme_skills="`alfa-um`", readme_raiz="`alfa-um` 1 skills")
        self.assertTrue(any("difere do diretório" in x for x in p))

    def test_referencia_com_erro_de_digitacao(self):
        p = self.rodar(skills={"alfa-um": skill("alfa-um", "use `alfa-uum`")}, readme_skills="`alfa-um`", readme_raiz="`alfa-um`")
        self.assertTrue(any("quis dizer `alfa-um`" in x for x in p))

    def test_skill_fora_do_indice_e_contagem_errada(self):
        p = self.rodar(skills={"alfa-um": skill("alfa-um")}, readme_skills="nada", readme_raiz="19 skills `alfa-um`")
        self.assertTrue(any("não aparece" in x for x in p))
        self.assertTrue(any("declara 19 skills" in x for x in p))

    def test_link_quebrado(self):
        p = self.rodar(skills={"alfa-um": skill("alfa-um")}, readme_skills="`alfa-um` [x](./nao-existe/SKILL.md)", readme_raiz="`alfa-um`")
        self.assertTrue(any("link quebrado" in x for x in p))

    def test_comando_copiado_no_readme(self):
        cmd = f"---\ndescription: d\n---\n{CORPO_CMD}\n"
        p = self.rodar(skills={"alfa-um": skill("alfa-um")}, readme_skills="`alfa-um`\n" + CORPO_CMD, readme_raiz="`alfa-um`",
                       comandos={"x.md": cmd})
        self.assertTrue(any("copia texto" in x for x in p))

    def test_script_citado_inexistente(self):
        p = self.rodar(skills={"alfa-um": skill("alfa-um", "rode `python3 .opencode/skills/alfa-um/x.py`")},
                       readme_skills="`alfa-um`", readme_raiz="`alfa-um`")
        self.assertTrue(any("script citado não existe" in x for x in p))

    def test_orcamento_de_tamanho(self):
        p = self.rodar(skills={"alfa-um": skill("alfa-um", "x" * (vs.ORCAMENTO_BYTES + 10))},
                       readme_skills="`alfa-um`", readme_raiz="`alfa-um`")
        self.assertTrue(any("orçamento" in x for x in p))

    def test_trava_de_seguranca_removida(self):
        p = self.rodar(skills={"gestao-segredos": skill("gestao-segredos", "texto sem as regras")},
                       readme_skills="`gestao-segredos`", readme_raiz="`gestao-segredos`")
        self.assertEqual(sum("trava de segurança ausente" in x for x in p), 2)
        ok = self.rodar(skills={"gestao-segredos": skill("gestao-segredos", "Nunca copie o valor. Não rotacione sozinho.")},
                        readme_skills="`gestao-segredos`", readme_raiz="`gestao-segredos`")
        self.assertFalse(any("trava" in x for x in ok))


if __name__ == "__main__":
    unittest.main(verbosity=2)
